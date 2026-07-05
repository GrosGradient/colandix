import json

from colandix.logger import ColandixLogger
from colandix.result import Action, PipelineConfig, ScanDirection, ScanResult


def make_scan_result(direction=ScanDirection.INPUT, blocked=False):
    """Helper pour créer un ScanResult de test."""
    return ScanResult(
        direction=direction,
        original_text="texte original — jamais loggué",
        sanitized_text="texte sanitized",
        blocked=blocked,
        action=Action.BLOCK if blocked else Action.PASS,
        global_score=1.0 if blocked else 0.0,
        events=[],
        reason="Test" if blocked else None,
    )


def test_logger_init_defaut():
    config = PipelineConfig()
    logger = ColandixLogger(config)
    assert logger._file_path is None


def test_hash_user_retourne_16_chars():
    config = PipelineConfig()
    logger = ColandixLogger(config)
    h = logger._hash_user("alice")
    assert h is not None
    assert len(h) == 16


def test_hash_user_none_retourne_none():
    config = PipelineConfig()
    logger = ColandixLogger(config)
    assert logger._hash_user(None) is None


def test_hash_user_deterministe():
    config = PipelineConfig()
    logger = ColandixLogger(config)
    assert logger._hash_user("alice") == logger._hash_user("alice")


def test_hash_user_different_pour_users_differents():
    config = PipelineConfig()
    logger = ColandixLogger(config)
    assert logger._hash_user("alice") != logger._hash_user("bob")


def test_log_structure_json_valide():
    config = PipelineConfig()
    logger = ColandixLogger(config)
    result = make_scan_result()
    emitted = []

    def fake_emit(entry):
        emitted.append(entry)

    logger._emit = fake_emit
    logger.log(result, user_id="alice")
    assert len(emitted) == 1
    entry = emitted[0]
    assert "event_id" in entry
    assert "timestamp" in entry
    assert "direction" in entry
    assert "blocked" in entry
    assert "action" in entry
    assert "global_score" in entry
    assert "anssi_framework" in entry
    assert entry["anssi_framework"] == "ANSSI-PA-102"


def test_log_ne_contient_pas_texte_original():
    config = PipelineConfig()
    logger = ColandixLogger(config)
    result = make_scan_result()
    emitted = []
    logger._emit = lambda e: emitted.append(e)
    logger.log(result)
    entry = emitted[0]
    assert "original_text" not in entry
    assert "sanitized_text" not in entry
    assert "texte original" not in json.dumps(entry)


def test_log_skip_si_log_inputs_false():
    config = PipelineConfig(log_inputs=False)
    logger = ColandixLogger(config)
    result = make_scan_result(direction=ScanDirection.INPUT)
    emitted = []
    logger._emit = lambda e: emitted.append(e)
    logger.log(result)
    assert len(emitted) == 0


def test_log_skip_si_log_outputs_false():
    config = PipelineConfig(log_outputs=False)
    logger = ColandixLogger(config)
    result = make_scan_result(direction=ScanDirection.OUTPUT)
    emitted = []
    logger._emit = lambda e: emitted.append(e)
    logger.log(result)
    assert len(emitted) == 0


def test_log_output_non_skippe_si_log_outputs_true():
    config = PipelineConfig(log_outputs=True)
    logger = ColandixLogger(config)
    result = make_scan_result(direction=ScanDirection.OUTPUT)
    emitted = []
    logger._emit = lambda e: emitted.append(e)
    logger.log(result)
    assert len(emitted) == 1


def test_to_file_retourne_self():
    config = PipelineConfig()
    logger = ColandixLogger(config)
    returned = logger.to_file("/tmp/test_colandix.jsonl")
    assert returned is logger
    assert logger._file_path == "/tmp/test_colandix.jsonl"


def test_emit_ecrit_json_valide_dans_fichier(tmp_path):
    config = PipelineConfig()
    logger = ColandixLogger(config)
    log_file = tmp_path / "audit.jsonl"
    logger.to_file(str(log_file))
    result = make_scan_result(blocked=True)
    logger.log(result, user_id="user123")
    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["blocked"] is True
