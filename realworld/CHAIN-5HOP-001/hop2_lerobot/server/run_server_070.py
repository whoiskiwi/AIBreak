"""Start the REAL lerobot 0.7.0 remote-inference policy server (patched).

0.7.0 removed the vulnerable async_inference gRPC service entirely
(CVE-2026-25874: policy_server.py pickle.loads(request.data)) and replaced it
with a zenoh transport + msgpack codec (remote_inference/). The server-side
decode path contains no pickle.loads of attacker bytes.

This script builds a minimal local ACT checkpoint, then starts the official
PolicyServer via the library's own ServerConfig/ZenohTransport classes.
"""
import logging

import torch

from lerobot.configs.types import FeatureType, PolicyFeature
from lerobot.policies.act.configuration_act import ACTConfig
from lerobot.policies.factory import get_policy_class
from lerobot.remote_inference import ModelConfig, ServerConfig, SessionWorker, load_deployment
from lerobot.remote_inference.server import PolicyServer
from lerobot.transport import ZenohConfig
from lerobot.transport.zenoh import ZenohTransport
from lerobot.utils.feature_spec import FeatureSpec


def make_checkpoint(tmp="/tmp/act-min") -> str:
    cfg = ACTConfig(
        input_features={
            "observation.state": PolicyFeature(type=FeatureType.STATE, shape=(7,)),
            "observation.images.top": PolicyFeature(type=FeatureType.VISUAL, shape=(3, 96, 96)),
        },
        output_features={"action": PolicyFeature(type=FeatureType.ACTION, shape=(7,))},
        chunk_size=4,
        n_action_steps=4,
        n_obs_steps=1,
        pretrained_backbone_weights=None,
    )
    cls = get_policy_class("act")
    policy = cls(cfg)
    policy.save_pretrained(tmp)
    # 0.7.0 policy loading requires processor-format normalization metadata.
    import subprocess, sys as _sys

    subprocess.run(
        [
            _sys.executable,
            "-m",
            "lerobot.processor.migrate_policy_normalization",
            f"--pretrained-path={tmp}",
            f"--output-dir={tmp}_migrated",
        ],
        check=True,
    )
    return f"{tmp}_migrated"


def main():
    path = make_checkpoint()
    cfg = ServerConfig(
        deployment="chain5hop",
        semantics="hop2-fix-verification",
        model=ModelConfig(repo_or_path=path, device="cpu"),
        features=[
            FeatureSpec(name="observation.state", shape=(7,), dtype="float32", semantics="state7"),
            FeatureSpec(
                name="observation.images.top",
                shape=(96, 96, 3),
                dtype="uint8",
                kind="rgb",
                semantics="camtop",
            ),
        ],
        action_feature=FeatureSpec(name="action", shape=(7,), dtype="float32", semantics="act7"),
        zenoh=ZenohConfig(mode="peer", listen_endpoints=["tcp/0.0.0.0:7447"]),
    )
    runner, identity = load_deployment(cfg)
    worker = SessionWorker(
        runner,
        deployment=cfg.deployment,
        artifact_identity=identity,
        semantics=cfg.semantics,
        action_deadline_s=cfg.execution.action_deadline_s,
        language_deadline_s=cfg.language.deadline_s,
        idle_timeout_s=cfg.execution.idle_timeout_s,
        max_input_chars=cfg.language.max_input_chars,
        max_output_chars=cfg.language.max_output_chars,
    )
    server = PolicyServer(worker, ZenohTransport(cfg.zenoh))
    logging.basicConfig(level=logging.INFO)
    server.serve()


if __name__ == "__main__":
    main()
