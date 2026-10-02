import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as app_module
from app import (UnsupportedProjectError, enclosure_stl, kicad_drc, make_svg,
                 project_preflight, selected_project_leds, validate_part_catalog)
from board_compiler import compile_board


def part(reference, kind, value=None):
    return {"reference": reference, "kind": kind, "value": value or kind,
            "description": "test part", "quantity": 1}


class BoardCompilerAcceptanceTests(unittest.TestCase):
    def assert_board_passes(self, design, style, enclosure=False):
        board = compile_board(design, style, enclosure)
        report = kicad_drc(board)
        self.assertEqual([], report.get("violations", []))
        self.assertEqual([], report.get("unconnected_items", []))
        svg = make_svg(board, "B.Cu", True, True, True)
        self.assertIn('id="copper-to-expose"', svg)
        if enclosure:
            self.assertEqual(4, board.count("np_thru_hole"))
            self.assertIn('id="drill-centers"', svg)
        return board

    def test_surface_mount_light_sensor_with_enclosure(self):
        saved = json.loads(Path("/data/generated/c8051a596c/project.json").read_text())
        design = {key: value for key, value in saved["design"].items() if key != "kicad_pcb"}
        board = self.assert_board_passes(design, "surface-mount", True)
        self.assertIn('(gr_rect (start 0 0) (end 98 70)', board)
        self.assertIn('(size 1.20 1.40)', board)
        svg = make_svg(board, "B.Cu", True, True, True)
        self.assertGreaterEqual(svg.count("<circle"), 4 + board.count("(via "))

    def test_through_hole_555_led_oscillator(self):
        design = {
            "components": [part("J1", "connector2"), part("U1", "ic8", "NE555 DIP-8"),
                           part("R1", "resistor", "10 kΩ"), part("R2", "resistor", "100 kΩ"),
                           part("R3", "resistor", "470 Ω"), part("C1", "capacitor", "10 µF"),
                           part("C2", "capacitor", "100 nF"), part("D1", "led", "Red LED")],
            "nets": [
                {"name": "VCC", "endpoints": ["J1.1", "U1.8", "U1.4", "R1.1"]},
                {"name": "GND", "endpoints": ["J1.2", "U1.1", "C1.2", "C2.2", "D1.2"]},
                {"name": "DISCHARGE", "endpoints": ["R1.2", "R2.1", "U1.7"]},
                {"name": "TIMING", "endpoints": ["R2.2", "C1.1", "U1.2", "U1.6"]},
                {"name": "CONTROL", "endpoints": ["U1.5", "C2.1"]},
                {"name": "OUTPUT", "endpoints": ["U1.3", "R3.1"]},
                {"name": "LED", "endpoints": ["R3.2", "D1.1"]},
            ],
        }
        board = self.assert_board_passes(design, "through-hole")
        self.assertIn('(at 8.00 8.00)', board)
        self.assertIn('(at 13.08 8.00)', board)
        self.assertIn('(at 30.62 8.00)', board)

    def test_surface_mount_transistor_switch(self):
        design = {
            "components": [part("J1", "connector2"), part("Q1", "transistor", "MMBT3904"),
                           part("R1", "resistor", "10 kΩ"), part("R2", "resistor", "470 Ω"),
                           part("D1", "led", "Yellow 0805 LED"), part("SW1", "switch2")],
            "nets": [
                {"name": "VCC", "endpoints": ["J1.1", "R2.1", "SW1.1"]},
                {"name": "GND", "endpoints": ["J1.2", "Q1.2", "R1.2"]},
                {"name": "BASE", "endpoints": ["SW1.2", "R1.1", "Q1.1"]},
                {"name": "LED_A", "endpoints": ["R2.2", "D1.1"]},
                {"name": "LED_K", "endpoints": ["D1.2", "Q1.3"]},
            ],
        }
        board = self.assert_board_passes(design, "surface-mount", True)
        self.assertIn('(size 1.00 1.20)', board)

    def test_seven_led_heart_chaser(self):
        components = [
            part("J1", "connector2", "5 V input"),
            part("U1", "ic14", "CD40106 SOIC-14"),
            part("U2", "ic16", "CD4017 SOIC-16"),
            part("R1", "resistor", "1 MΩ 0805"),
            part("C1", "capacitor", "1 µF 0805"),
            part("C2", "capacitor", "100 nF 0805"),
            part("R2", "resistor", "1 kΩ shared LED resistor"),
        ] + [part(f"D{index}", "led", "Red 0805 LED") for index in range(1, 8)]
        nets = [
            {"name": "+5V", "endpoints": ["J1.1", "U1.14", "U2.16", "C2.1"]},
            {"name": "GND", "endpoints": ["J1.2", "U1.7", "U1.3", "U1.5", "U1.9",
                                             "U1.11", "U1.13", "U2.8", "U2.13", "C1.2",
                                             "C2.2", "R2.2"]},
            {"name": "OSC_TIMING", "endpoints": ["U1.1", "R1.1", "C1.1"]},
            {"name": "CLOCK", "endpoints": ["U1.2", "R1.2", "U2.14"]},
            {"name": "RESET_AFTER_7", "endpoints": ["U2.6", "U2.15"]},
            {"name": "LED_RETURN", "endpoints": ["R2.1"] + [f"D{index}.1" for index in range(1, 8)]},
        ]
        for index, pin in enumerate((3, 2, 4, 7, 10, 1, 5), 1):
            nets.append({"name": f"LED{index}_DRIVE", "endpoints": [f"U2.{pin}", f"D{index}.2"]})
        design = {"components": components, "nets": nets, "layout_shape": "heart"}
        board = self.assert_board_passes(design, "surface-mount", True)
        for x, y in ((34, 16), (64, 16), (76, 30), (68, 48),
                     (49, 61), (30, 48), (22, 30)):
            self.assertIn(f'(at {x - 1:.2f} {y:.2f})', board)
        self.assertIn('(end 98 73)', board)

    def test_safety_and_real_part_gates(self):
        with self.assertRaises(UnsupportedProjectError):
            project_preflight({"idea": "make a lithium battery charger with protection"})
        with self.assertRaises(UnsupportedProjectError):
            validate_part_catalog({"components": [part("U1", "ic8", "MCP73123 charger")]})
        validate_part_catalog({"components": [part("U1", "ic8", "NE555 timer")]})

    def test_led_choice_is_optional_and_user_api_key_is_private(self):
        self.assertEqual([], selected_project_leds({"led": None, "leds": []}))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app_module, "PROJECTS_FILE", Path(directory) / "projects.json"), \
                patch.object(app_module, "AUTH_DB", Path(directory) / "auth.db"), \
                patch.object(app_module, "write_project_status"), \
                patch.object(app_module.threading, "Thread") as thread:
            app_module.init_auth_db()
            encrypted = app_module._key_cipher().encrypt(b"temporary-test-secret").decode("ascii")
            with app_module.auth_connection() as connection:
                cursor = connection.execute(
                    "INSERT INTO users(email,password_hash,status,role,api_key_cipher,created_at) "
                    "VALUES(?,?, 'approved','admin',?,?)",
                    ("builder@example.com", app_module.generate_password_hash("long-test-password"),
                     encrypted, "2026-10-01T00:00:00+00:00"),
                )
                user_id = cursor.lastrowid
            app_module.app.config["TESTING"] = True
            try:
                client = app_module.app.test_client()
                with client.session_transaction() as browser_session:
                    browser_session["user_id"] = user_id
                response = client.post("/build/plan", data={
                    "idea": "A temperature alarm with no light",
                    "parts": "shopping", "style": "through-hole", "enclosure": "no",
                })
                self.assertEqual(303, response.status_code)
                saved = (Path(directory) / "projects.json").read_text()
                self.assertNotIn("temporary-test-secret", saved)
                runtime_project = thread.call_args.kwargs["args"][0]
                self.assertEqual("temporary-test-secret", runtime_project["_api_key"])
                self.assertEqual(user_id, json.loads(saved)[0]["owner_id"])
                self.assertIsNone(json.loads(saved)[0]["led"])
            finally:
                app_module.app.config["TESTING"] = False

    def test_enclosure_stl_has_base_lid_standoffs_and_battery_space(self):
        project = {"id": "1234567890", "idea": "9 V battery alarm", "enclosure": True}
        design = {
            "title": "Alarm", "supply": "9 V battery",
            "components": [part("J1", "connector2"), part("U1", "ic8")],
        }
        text, spec = enclosure_stl(project, design)
        self.assertTrue(text.startswith("solid pcb_enclosure"))
        self.assertTrue(text.endswith("endsolid pcb_enclosure\n"))
        self.assertGreater(text.count("facet normal"), 200)
        self.assertIsNotNone(spec["battery"])
        self.assertGreater(spec["outer_width"], spec["board"]["width"] + 20)
        self.assertEqual(4, len(spec["board"]["holes"]))

    def test_registration_requires_admin_approval_and_each_user_key(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app_module, "AUTH_DB", Path(directory) / "auth.db"), \
                patch.object(app_module.threading, "Thread"):
            app_module.init_auth_db()
            with app_module.auth_connection() as connection:
                cursor = connection.execute(
                    "INSERT INTO users(email,password_hash,status,role,created_at) "
                    "VALUES(?,?, 'approved','admin',?)",
                    ("admin@example.com", app_module.generate_password_hash("admin-password-123"),
                     "2026-10-01T00:00:00+00:00"),
                )
                admin_id = cursor.lastrowid
            app_module.app.config["TESTING"] = True
            try:
                applicant = app_module.app.test_client()
                response = applicant.post("/register", data={
                    "email": "new@example.com", "password": "new-user-password-123",
                    "confirm_password": "new-user-password-123",
                })
                self.assertEqual(200, response.status_code)
                blocked = applicant.post("/login", data={
                    "email": "new@example.com", "password": "new-user-password-123",
                })
                self.assertIn(b"awaiting approval", blocked.data)

                administrator = app_module.app.test_client()
                with administrator.session_transaction() as browser_session:
                    browser_session["user_id"] = admin_id
                with app_module.auth_connection() as connection:
                    user_id = connection.execute(
                        "SELECT id FROM users WHERE email='new@example.com'"
                    ).fetchone()["id"]
                approved = administrator.post("/admin", data={
                    "action": "approve", "user_id": str(user_id),
                })
                self.assertEqual(200, approved.status_code)

                signed_in = applicant.post("/login", data={
                    "email": "new@example.com", "password": "new-user-password-123",
                })
                self.assertEqual(303, signed_in.status_code)
                builder = applicant.get("/build")
                self.assertIn(b"Prompt-based project creation is disabled", builder.data)
                applicant.post("/settings", data={"action": "save-key", "api_key": "user-owned-key"})
                with app_module.auth_connection() as connection:
                    cipher = connection.execute(
                        "SELECT api_key_cipher FROM users WHERE id=?", (user_id,)
                    ).fetchone()["api_key_cipher"]
                self.assertNotIn("user-owned-key", cipher)
                self.assertEqual("user-owned-key", app_module.user_api_key(user_id))
            finally:
                app_module.app.config["TESTING"] = False


if __name__ == "__main__":
    unittest.main()
