"""Canonical node/parameter schema — the single source of truth for
architecture validation.

This registry is serialized to ``info/contracts/component-schema.json`` by
``generate.py`` and *interpreted* (never re-implemented) by the backend
validator (``interpret.validate_params``) and the frontend validator
(``schema-param-validation.ts``). One definition of every parameter
constraint, one message set, three runtimes that cannot disagree. EDIT HERE.

Casing note
-----------
Parameter ``key`` values are written exactly as they appear in the frontend
component library (``mvp-frontend/.../data/component-library``), which is the
form actually persisted in diagram state — predominantly camelCase
(``kernelSize``) with some snake_case (``weight_decay``). The interpreters
resolve a key case-insensitively across camelCase/snake_case variants (plus
any explicit ``aliases``), so a single schema reads both the frontend's
camelCase configs and the backend's historical snake_case configs.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

ParamKind = Literal["number", "enum", "padding", "bool", "string"]


class NumericConstraint(BaseModel):
    """Bounds for a numeric parameter. ``integer`` forbids fractional values.

    ``min``/``max`` are HARD bounds (outside -> error). ``warn_min``/``warn_max``
    are SOFT, advisory bounds inside the hard range: a value that is valid but
    atypical (e.g. dropout 0.95, learning-rate 0.5) yields a non-blocking
    WARNING, never an error. Both interpreters read these from the generated
    schema, so the advisory is single-sourced like every other constraint.
    """

    min: float | None = None
    max: float | None = None
    integer: bool = False
    warn_min: float | None = None
    warn_max: float | None = None


class Advisory(BaseModel):
    """A categorical advisory: when this param's value equals ``when_value``
    (case-insensitive), emit diagnostic ``code`` (an info/warning catalog entry).
    Lets a *valid* enum choice carry a non-blocking note — e.g.
    ``lr_scheduler_type = 'none'`` -> ``INFO_NO_LR_SCHEDULE``. Single-sourced in
    the schema; all three runtimes emit it identically."""

    when_value: str
    code: str


class ParamSpec(BaseModel):
    """A single configurable parameter of a component."""

    key: str
    kind: ParamKind
    required: bool = False
    default: object | None = None
    numeric: NumericConstraint | None = None
    enum_values: list[str] | None = None
    # True synonyms for ``key`` (beyond camelCase/snake_case variants, which
    # are resolved automatically). E.g. dropout accepts ``p`` for ``rate``.
    aliases: list[str] | None = None
    # {controlling_param: [values for which THIS param applies]}; when the
    # controlling param's value is outside the list, this param is inactive
    # (not shown in the UI, not validated). Comparison is case-insensitive.
    applies_when: dict[str, list[str]] | None = None
    # Non-blocking categorical advisories keyed on this param's value.
    advisories: list[Advisory] | None = None


ParamFormulaKind = Literal[
    "none",
    "conv",
    "depthwise_separable_conv",
    "dense",
    "attention",
    "embedding",
    "norm",
    "rnn",
    "ffn",
    "moe",
    "lora",
    "timestep_embedding",
    "cls_token",
]


class ParamFormula(BaseModel):
    """Declarative descriptor of how to COUNT a component's trainable parameters.

    The estimator (TS frontend + Python mirror) dispatches on ``kind`` and reads
    conventional config keys for that kind; ``roles`` overrides a logical role ->
    actual config key where a component diverges from the convention (e.g.
    ``ffn-block`` uses ``dFf``, ``rms-normalization`` is scale-only,
    ``patch-embedding`` binds ``filters -> embed_dim``). A ``roles`` value may also
    be a literal scalar the estimator interprets per-kind (e.g. ``"4"`` gates,
    ``"scale_only"`` affine). NO per-component branch lives in the estimator —
    components plug in here.
    """

    kind: ParamFormulaKind
    roles: dict[str, str] = {}


class ComponentSpec(BaseModel):
    """The validation contract for one studio component."""

    component_id: str
    layer_type: str
    params: list[ParamSpec]
    param_formula: ParamFormula | None = None
    # Graph input-topology: does this component need an incoming connection to be
    # "connected"? Source-like nodes (e.g. a timestep embedding whose only input
    # is an external scalar, declared optional) legitimately have no incoming
    # edge, so the connectivity check must NOT flag them as disconnected. Mirrors
    # the frontend's ``inputs.some(i => i.required)`` (component-config.ts); a
    # parity test keeps the two in sync. Defaults to True (the common case).
    requires_incoming_input: bool = True


# --- Compact builders (keep the registry readable) --------------------------


def _num(
    key: str,
    *,
    lo: float | None = None,
    hi: float | None = None,
    integer: bool = False,
    required: bool = False,
    aliases: list[str] | None = None,
    applies_when: dict[str, list[str]] | None = None,
    warn_lo: float | None = None,
    warn_hi: float | None = None,
) -> ParamSpec:
    return ParamSpec(
        key=key,
        kind="number",
        required=required,
        numeric=NumericConstraint(
            min=lo, max=hi, integer=integer, warn_min=warn_lo, warn_max=warn_hi
        ),
        aliases=aliases,
        applies_when=applies_when,
    )


def _enum(
    key: str,
    values: list[object],
    *,
    applies_when: dict[str, list[str]] | None = None,
    advisories: list[Advisory] | None = None,
) -> ParamSpec:
    return ParamSpec(
        key=key,
        kind="enum",
        enum_values=[str(v) for v in values],
        applies_when=applies_when,
        advisories=advisories,
    )


def _pad(key: str = "padding") -> ParamSpec:
    return ParamSpec(key=key, kind="padding")


def _bool(key: str, *, advisories: list[Advisory] | None = None) -> ParamSpec:
    return ParamSpec(key=key, kind="bool", advisories=advisories)


def _text(key: str) -> ParamSpec:
    return ParamSpec(key=key, kind="string")


# --- The canonical component registry ---------------------------------------
#
# Constraints below are translated verbatim from the frontend component
# library's ``parameters[].validation`` (min/max/integer) and ``options``
# (enum values). ``required`` is reserved for structurally essential params
# (mirroring the backend's historical conv/dense checks); everything else is
# validated only when present.

_SPECS: list[ComponentSpec] = [
    # ----- Convolutional family -----
    ComponentSpec(
        component_id="convolution-layer",
        param_formula=ParamFormula(kind="conv"),
        layer_type="conv2d",
        params=[
            _enum("dimensions", ["1d", "2d", "3d"]),
            _num("filters", lo=1, hi=2048, integer=True, required=True, warn_hi=1024),
            _num("kernelSize", lo=1, hi=11, integer=True, required=True),
            _num("stride", lo=1, hi=10, integer=True),
            _pad(),
            # "linear" (identity) is a valid conv activation used by real
            # architectures (e.g. final projection convs); the UI dropdown omits
            # it, so the canonical enum reflects the broader valid set.
            _enum(
                "activation",
                ["none", "relu", "sigmoid", "tanh", "linear"],
                advisories=[
                    Advisory(when_value="none", code="INFO_LINEAR_ACTIVATION"),
                    Advisory(when_value="linear", code="INFO_LINEAR_ACTIVATION"),
                ],
            ),
        ],
    ),
    ComponentSpec(
        component_id="transposed-convolution",
        param_formula=ParamFormula(kind="conv"),
        layer_type="conv2d_transpose",
        params=[
            _enum("dimensions", ["2d", "3d"]),
            _num("filters", lo=1, hi=2048, integer=True, required=True, warn_hi=1024),
            _num("kernelSize", lo=1, hi=11, integer=True, required=True),
            _num("stride", lo=1, hi=10, integer=True),
            _pad(),
        ],
    ),
    ComponentSpec(
        component_id="depthwise-separable-conv",
        param_formula=ParamFormula(kind="depthwise_separable_conv"),
        layer_type="depthwise_conv2d",
        params=[
            _enum("dimensions", ["1d", "2d"]),
            _num("filters", lo=1, hi=2048, integer=True, required=True, warn_hi=1024),
            _num("kernelSize", lo=1, hi=11, integer=True, required=True),
            _num("stride", lo=1, hi=10, integer=True),
            _pad(),
            _num("depthMultiplier", lo=1, hi=8, integer=True),
            _enum("activation", ["none", "relu", "relu6", "sigmoid", "tanh", "swish", "linear"]),
        ],
    ),
    ComponentSpec(
        component_id="upsample-layer",
        layer_type="upsample",
        params=[
            _num("scaleFactor", lo=1, hi=16, integer=True),
            _enum("mode", ["nearest", "bilinear", "bicubic", "trilinear"]),
            _enum("dimensions", ["1d", "2d", "3d"]),
            _bool("alignCorners"),
        ],
    ),
    # ----- Dense / output -----
    ComponentSpec(
        component_id="dense-layer",
        param_formula=ParamFormula(kind="dense", roles={"bias": "useBias"}),
        layer_type="dense",
        params=[
            # Deliberately uncapped: a Dense layer's width is a modelling choice
            # (an LM head is vocab-sized, often 32k-256k), not a platform limit.
            # The lower bound stays because units < 1 is meaningless.
            _num("units", lo=1, integer=True, required=True),
            _enum(
                "activation",
                ["relu", "sigmoid", "tanh", "softmax", "linear"],
                advisories=[Advisory(when_value="linear", code="INFO_LINEAR_ACTIVATION")],
            ),
            _bool("useBias"),
        ],
    ),
    ComponentSpec(
        component_id="output-layer",
        layer_type="output",
        params=[
            _enum(
                "outputType",
                ["classification", "regression", "segmentation", "language_modeling", "generation"],
            ),
            _num("numClasses", lo=1, hi=10000, integer=True),
            _num("vocabSize", lo=2, hi=1000000, integer=True),
            _num("sequenceLength", lo=2, hi=8192, integer=True),
            _enum("optimizer", ["adam", "sgd", "rmsprop", "adamw", "adagrad"]),
            _num(
                "optimizer_momentum",
                lo=0.0,
                hi=0.999,
                applies_when={"optimizer": ["sgd", "rmsprop"]},
            ),
            _num("learningRate", lo=1e-8, hi=1.0, warn_lo=1e-5, warn_hi=0.1),
            _num("epochs", lo=1, hi=1000, integer=True, warn_hi=500),
            _num("batchSize", lo=1, hi=2048, integer=True),
            _num("warmup_epochs", lo=0, hi=100, integer=True),
            _bool("regularization_enabled"),
            # weight_decay is only meaningful for optimizers that implement a
            # decoupled/L2 decay term; plain Adam users switch to AdamW instead.
            _num(
                "weight_decay",
                lo=0.0,
                hi=1.0,
                warn_hi=0.1,
                applies_when={"optimizer": ["adamw", "sgd", "rmsprop"]},
            ),
            _num("gradient_clip_value", lo=0, hi=100, warn_hi=10),
            _num("early_stopping_patience", lo=1, hi=100, integer=True),
            _num("gradient_accumulation_steps", lo=1, hi=128, integer=True),
            _num("num_gpus", lo=0, hi=8, integer=True),
            _num("num_nodes", lo=1, hi=16, integer=True),
            _num("save_frequency_epochs", lo=1, hi=100, integer=True),
            _num("max_checkpoints", lo=1, hi=50, integer=True),
            _num("log_frequency", lo=1, hi=1000, integer=True),
            _enum("device", ["cuda", "cpu", "mps", "tpu"]),
            _enum(
                "mixed_precision",
                ["no", "fp16", "bf16"],
                advisories=[Advisory(when_value="no", code="INFO_MIXED_PRECISION_OFF")],
            ),
            _enum("training_library", ["none", "accelerate", "deepspeed", "fsdp"]),
            _enum(
                "lr_scheduler_type",
                [
                    "none",
                    "reduce_on_plateau",
                    "cosine_annealing",
                    "warmup_decay",
                    "onecycle",
                    # Legacy persisted graphs are normalized on load. Keep
                    # their former labels valid at the contract boundary so
                    # validation does not reject a diagram before migration.
                    "step",
                    "exponential",
                    "cosine",
                    "plateau",
                ],
                advisories=[Advisory(when_value="none", code="INFO_NO_LR_SCHEDULE")],
            ),
            _enum(
                "postProcessing",
                ["none", "softmax", "sigmoid", "argmax", "beam_search", "top_k_sampling"],
            ),
            _enum("log_level", ["DEBUG", "INFO", "WARNING", "ERROR"]),
        ],
    ),
    # ----- Regularization -----
    ComponentSpec(
        component_id="dropout",
        layer_type="dropout",
        params=[
            _num("rate", lo=0, hi=1, aliases=["p"], warn_hi=0.7),
            _enum("dropoutMode", ["standard", "spatial1d", "spatial2d", "spatial3d"]),
            _num("seed", lo=0, hi=999999, integer=True),
        ],
    ),
    ComponentSpec(
        component_id="l1-regularization",
        layer_type="l1_regularization",
        params=[_num("l1", lo=0, hi=1)],
    ),
    ComponentSpec(
        component_id="l2-regularization",
        layer_type="l2_regularization",
        params=[_num("l2", lo=0, hi=1)],
    ),
    ComponentSpec(
        component_id="stochastic-depth",
        layer_type="stochastic_depth",
        params=[_num("drop_prob", lo=0.0, hi=1.0, warn_hi=0.5)],
    ),
    # ----- Normalization -----
    ComponentSpec(
        component_id="batch-normalization",
        param_formula=ParamFormula(
            kind="norm", roles={"scope": "channel", "affine": "scale,center"}
        ),
        layer_type="batch_normalization",
        params=[
            _num("momentum", lo=0, hi=1),
            _num("epsilon", lo=1e-10, hi=1e-1),
            _bool("center"),
            _bool("scale"),
        ],
    ),
    ComponentSpec(
        component_id="layer-normalization",
        param_formula=ParamFormula(
            kind="norm", roles={"scope": "feature", "affine": "scale,center"}
        ),
        layer_type="layer_normalization",
        params=[
            _num("epsilon", lo=1e-10, hi=1e-3),
            _bool("center"),
            _bool("scale"),
        ],
    ),
    ComponentSpec(
        component_id="instance-normalization",
        param_formula=ParamFormula(
            kind="norm", roles={"scope": "channel", "affine": "scale,center"}
        ),
        layer_type="instance_normalization",
        params=[
            _num("epsilon", lo=1e-10, hi=1e-3),
            _bool(
                "affine",
                advisories=[Advisory(when_value="false", code="INFO_NO_NORMALIZATION_AFFINE")],
            ),
        ],
    ),
    ComponentSpec(
        component_id="rms-normalization",
        param_formula=ParamFormula(kind="norm", roles={"scope": "feature", "affine": "scale_only"}),
        layer_type="rms_normalization",
        params=[_num("epsilon", lo=1e-10, hi=1e-3)],
    ),
    ComponentSpec(
        component_id="group-normalization",
        param_formula=ParamFormula(
            kind="norm", roles={"scope": "channel", "affine": "scale,center"}
        ),
        layer_type="group_normalization",
        params=[_num("numGroups", lo=1, hi=128, integer=True), _num("epsilon", lo=1e-10, hi=1e-3)],
    ),
    # ----- Pooling / shape utilities -----
    ComponentSpec(
        component_id="pooling-layer",
        layer_type="pooling",
        params=[
            _enum("poolingType", ["max", "average", "global_max", "global_average"]),
            _enum("dimensions", ["1d", "2d", "3d"]),
            _num("poolSize", lo=1, hi=10, integer=True),
            _num("stride", lo=1, hi=10, integer=True),
            # NOTE: pooling padding is a simple valid/same enum, NOT a typed
            # Padding object (only conv-family layers take typed padding).
            _enum("padding", ["valid", "same"]),
        ],
    ),
    ComponentSpec(
        component_id="unpooling-layer",
        layer_type="unpooling",
        params=[_enum("dimensions", ["2d"]), _num("poolSize", lo=1, hi=10, integer=True)],
    ),
    ComponentSpec(
        component_id="flatten",
        layer_type="flatten",
        params=[_num("startDim", lo=0, hi=8, integer=True)],
    ),
    ComponentSpec(
        component_id="reshape",
        layer_type="reshape",
        params=[_text("targetShape")],
    ),
    ComponentSpec(
        component_id="permute",
        layer_type="permute",
        params=[_text("dims")],
    ),
    ComponentSpec(
        component_id="merge-node",
        layer_type="merge",
        params=[
            _enum("operation", ["add", "concatenate", "multiply", "average"]),
            _num("axis", lo=-4, hi=4, integer=True),
        ],
    ),
    ComponentSpec(
        component_id="cls-extract",
        layer_type="cls_extract",
        params=[_num("position", lo=0, hi=8192, integer=True)],
    ),
    ComponentSpec(
        component_id="quantization-aware",
        layer_type="quantization_aware",
        params=[_enum("bits", [4, 8]), _enum("quantization_type", ["symmetric", "asymmetric"])],
    ),
    # ----- Activations -----
    ComponentSpec(
        component_id="activation-function",
        layer_type="activation",
        params=[
            _enum(
                "function",
                [
                    "relu",
                    "gelu",
                    "sigmoid",
                    "tanh",
                    "softmax",
                    "leaky_relu",
                    "clipped_relu",
                    "elu",
                    "swish",
                ],
            ),
            _num("clipValue", lo=0.1, hi=100),
            _num("alpha", lo=0, hi=1),
        ],
    ),
    ComponentSpec(
        component_id="swiglu-activation",
        layer_type="swiglu_activation",
        params=[_enum("variant", ["swiglu", "geglu"])],
    ),
    # ----- Attention -----
    ComponentSpec(
        component_id="multi-head-attention",
        param_formula=ParamFormula(
            kind="attention",
            roles={"heads": "numHeads", "head_dim": "keyDim", "kv_heads": "numKvHeads"},
        ),
        layer_type="multi_head_attention",
        params=[
            _num("numHeads", lo=1, hi=32, integer=True, warn_hi=16),
            _num("keyDim", lo=8, hi=512, integer=True),
            _num("dropout", lo=0, hi=1, warn_hi=0.5),
            _bool("useCausalMask"),
            _num("numKvHeads", lo=1, hi=32, integer=True),
            _bool("useKvCache"),
        ],
    ),
    ComponentSpec(
        component_id="cross-attention",
        param_formula=ParamFormula(kind="attention", roles={"heads": "num_heads"}),
        layer_type="cross_attention",
        params=[
            _num("query_dim", lo=1, hi=4096, integer=True),
            _num("context_dim", lo=1, hi=4096, integer=True),
            _num("num_heads", lo=1, hi=32, integer=True, warn_hi=16),
            _num("dropout", lo=0, hi=1, warn_hi=0.5),
        ],
    ),
    # ----- Embeddings / positional -----
    ComponentSpec(
        component_id="embedding-layer",
        param_formula=ParamFormula(
            kind="embedding", roles={"vocab": "vocabSize", "embed_dim": "embeddingDim"}
        ),
        layer_type="embedding",
        params=[
            _num("vocabSize", lo=1, hi=1000000, integer=True),
            _num("embeddingDim", lo=8, hi=2048, integer=True),
            _bool("maskZero"),
            _num("inputLength", lo=1, hi=10000, integer=True),
        ],
    ),
    ComponentSpec(
        component_id="positional-encoding",
        layer_type="positional_encoding",
        params=[
            _enum("encoding_type", ["sinusoidal", "learned"]),
            _num("max_len", lo=1, hi=32768, integer=True),
            _num("d_model", lo=1, hi=4096, integer=True),
        ],
    ),
    ComponentSpec(
        component_id="rope",
        layer_type="rope",
        params=[
            _num("dim", lo=1, hi=2048, integer=True),
            _num("base", integer=True),
            _num("max_seq_len", lo=1, hi=131072, integer=True),
        ],
    ),
    ComponentSpec(
        component_id="patch-embedding",
        # Roles read the camelCase config keys the shape engine uses (embedDim /
        # patchSize), so param estimation and shape inference agree on the same
        # projection dim — otherwise a fixture carrying both conventions would be
        # counted at one dim and shaped at another.
        param_formula=ParamFormula(
            kind="conv", roles={"filters": "embedDim", "kernel": "patchSize"}
        ),
        layer_type="patch_embedding",
        params=[
            _num("patch_size", lo=1, hi=64, integer=True),
            _num("embed_dim", lo=1, hi=4096, integer=True),
            _num("image_size", lo=1, hi=1024, integer=True),
        ],
    ),
    ComponentSpec(
        component_id="cls-token",
        # A learnable [1, 1, embed_dim] token contributes embed_dim trainable
        # params. The estimator reads the FE camelCase ``embedDim`` (default key).
        param_formula=ParamFormula(kind="cls_token", roles={"embed_dim": "embedDim"}),
        layer_type="cls_token",
        params=[_num("embed_dim", lo=1, hi=4096, integer=True)],
    ),
    ComponentSpec(
        component_id="timestep-embedding",
        # Sinusoidal time embedding projected through a 2-layer MLP:
        # Linear(time_dim->hidden_dim) + Linear(hidden_dim->hidden_dim). The
        # estimator reads the snake-case ``time_dim`` / ``hidden_dim`` codegen uses.
        param_formula=ParamFormula(
            kind="timestep_embedding", roles={"in": "time_dim", "hidden": "hidden_dim"}
        ),
        layer_type="timestep_embedding",
        # Source-like: its only input is the external diffusion timestep (a
        # scalar declared optional in the FE), so an isolated timestep embedding
        # is a dead end, not a "disconnected" node. Mirrors the FE component.
        requires_incoming_input=False,
        params=[
            _num("time_dim", lo=16, hi=1024, integer=True),
            _num("max_period", integer=True),
            _num("hidden_dim", lo=16, hi=4096, integer=True),
        ],
    ),
    # ----- Recurrent -----
    ComponentSpec(
        component_id="lstm-layer",
        param_formula=ParamFormula(kind="rnn", roles={"gates": "4"}),
        layer_type="lstm",
        params=[
            _num("units", lo=1, hi=2048, integer=True),
            _num("numLayers", lo=1, hi=8, integer=True),
            _bool("returnSequences"),
            _bool("bidirectional"),
            _num("dropout", lo=0, hi=1, warn_hi=0.5),
            _bool("useProjection"),
        ],
    ),
    ComponentSpec(
        component_id="gru-layer",
        param_formula=ParamFormula(kind="rnn", roles={"gates": "3"}),
        layer_type="gru",
        params=[
            _num("units", lo=1, hi=2048, integer=True),
            _num("numLayers", lo=1, hi=8, integer=True),
            _bool("returnSequences"),
            _num("dropout", lo=0, hi=1, warn_hi=0.5),
            _bool("useProjection"),
        ],
    ),
    # ----- Transformer / MoE blocks -----
    ComponentSpec(
        component_id="ffn-block",
        param_formula=ParamFormula(kind="ffn"),
        layer_type="ffn_block",
        params=[
            _num("dModel", lo=1, hi=8192, integer=True),
            _num("dFf", lo=1, hi=32768, integer=True),
            _enum("activation", ["relu", "swiglu", "geglu"]),
            _num("dropout", lo=0, hi=1, warn_hi=0.5),
        ],
    ),
    ComponentSpec(
        component_id="moe-layer",
        param_formula=ParamFormula(kind="moe"),
        layer_type="moe",
        params=[
            _num("num_experts", lo=2, hi=64, integer=True, warn_hi=32),
            _num("d_model", lo=1, hi=4096, integer=True),
            _num("d_ff", lo=1, hi=16384, integer=True),
            _num("top_k", lo=1, hi=64, integer=True),
            _enum("activation", ["relu", "swiglu", "gelu"]),
            _num("load_balance_weight", lo=0, hi=1),
        ],
    ),
    ComponentSpec(
        component_id="router-gating",
        layer_type="router_gating",
        params=[
            _num("num_experts", lo=2, hi=64, integer=True),
            _enum("routing_type", ["top_k_softmax", "noisy_top_k"]),
            _num("capacity_factor", lo=0.5, hi=4.0),
        ],
    ),
    ComponentSpec(
        component_id="lora-adapter",
        param_formula=ParamFormula(kind="lora"),
        layer_type="lora_adapter",
        params=[
            _num("rank", lo=1, hi=256, integer=True, warn_hi=128),
            _num("alpha", lo=1, hi=512, integer=True),
        ],
    ),
    # ----- Generative / diffusion / audio -----
    ComponentSpec(
        component_id="vae-reparameterization",
        layer_type="vae_reparameterization",
        params=[_num("latent_dim", lo=1, hi=1024, integer=True)],
    ),
    ComponentSpec(
        component_id="classifier-free-guidance",
        layer_type="classifier_free_guidance",
        params=[
            _num("guidance_scale", lo=1.0, hi=20.0, warn_hi=15.0),
            _num("uncond_prob", lo=0.0, hi=1.0),
        ],
    ),
    ComponentSpec(
        component_id="noise-scheduler",
        layer_type="noise_scheduler",
        params=[
            _enum("schedule_type", ["linear", "cosine"]),
            _num("num_timesteps", lo=10, hi=10000, integer=True),
            _num("beta_start"),
            _num("beta_end"),
        ],
    ),
    ComponentSpec(
        component_id="mel-spectrogram",
        layer_type="mel_spectrogram",
        params=[
            _num("n_fft", lo=128, hi=4096, integer=True),
            _num("hop_length", lo=64, hi=2048, integer=True),
            _num("n_mels", lo=16, hi=256, integer=True),
        ],
    ),
    ComponentSpec(
        component_id="mfcc",
        layer_type="mfcc",
        params=[
            _num("n_mfcc", lo=1, hi=40, integer=True),
            _num("n_fft", lo=128, hi=4096, integer=True),
            _num("hop_length", lo=64, hi=2048, integer=True),
        ],
    ),
]

COMPONENT_REGISTRY: dict[str, ComponentSpec] = {s.component_id: s for s in _SPECS}
