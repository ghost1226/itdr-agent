# Checklist — workflow diagram (Task B, 2026-10-23)

Task: add a Mermaid workflow diagram to PROJECT_BRIEF.md section 5 (Flow
diagram) in the brief's order — Alert, Pre-fetch (code), Investigator tool
loop, Dossier, Adjudicator, Guards (confidence, thin evidence, MITRE
evidence), Analyst question if needed, Containment review (approve / edit /
reject), Audit log — plus a test that the mermaid block names every stage. No
other prose changes.

- [x] the mermaid workflow block is in PROJECT_BRIEF.md -> `../PROJECT_BRIEF.md::flowchart TD`
- [x] the test extracts the mermaid block and checks every stage -> `../tests/test_project_brief.py::def test_the_diagram_names_every_stage`
- [x] PROGRESS.md records the task -> `../PROGRESS.md::workflow-diagram`
- [x] the red and green commits are recorded in PROGRESS.md -> `../PROGRESS.md::workflow-diagram: red`
- [x] full suite green and check_progress exits 0
