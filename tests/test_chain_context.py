"""Tests for the VectorChainContext Ogmios mapping."""

from fractions import Fraction

from vector_agent.chain.context import VectorChainContext, _convert_cost_models, _fraction


def test_fraction_parsing():
    assert _fraction("577/10000") == Fraction(577, 10000)
    assert _fraction("0/1") == Fraction(0)
    assert _fraction("1/100000") == Fraction(1, 100000)


def test_cost_model_conversion():
    ogmios = {
        "plutus:v1": [100, 200, 300],
        "plutus:v2": [400, 500],
    }
    result = _convert_cost_models(ogmios)
    assert "PlutusV1" in result
    assert "PlutusV2" in result
    assert result["PlutusV1"] == {"0": 100, "1": 200, "2": 300}
    assert result["PlutusV2"] == {"0": 400, "1": 500}


def test_protocol_params_mapping(sample_ogmios_protocol_params):
    pp = VectorChainContext._build_protocol_params(sample_ogmios_protocol_params)
    assert pp.min_fee_coefficient == 45
    assert pp.min_fee_constant == 156253
    assert pp.max_block_size == 180224
    assert pp.max_tx_size == 16384
    assert pp.max_block_header_size == 1100
    assert pp.key_deposit == 500000000
    assert pp.pool_deposit == 5000000000000
    assert pp.collateral_percent == 150
    assert pp.max_collateral_inputs == 3
    assert pp.coins_per_utxo_byte == 4310
    assert pp.protocol_major_version == 10
    assert pp.price_mem == Fraction(577, 10000)
    assert pp.price_step == Fraction(721, 10000000)
    assert pp.max_tx_ex_mem == 16000000
    assert pp.max_tx_ex_steps == 10000000000
    assert "PlutusV1" in pp.cost_models
    assert "PlutusV2" in pp.cost_models


def test_genesis_params_mapping(sample_ogmios_genesis):
    gp = VectorChainContext._build_genesis_params(sample_ogmios_genesis)
    assert gp.network_magic == 764824073
    assert gp.epoch_length == 86400
    assert gp.max_lovelace_supply == 3000000000000000
    assert gp.slot_length == 1  # 1000ms -> 1s
    assert gp.security_param == 2160
    assert gp.active_slots_coefficient == Fraction(1, 4)
    assert gp.system_start > 0  # Unix timestamp
