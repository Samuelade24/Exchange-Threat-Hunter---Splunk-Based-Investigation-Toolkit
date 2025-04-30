# -JHard-Pentest-Report-Generator-
Task: Auto-generate findings in DOCX 
from docx import Document

doc = Document()
doc.add_heading("Penetration Testing Report", level=1)
doc.add_paragraph("Critical Findings:", style="List Bullet")
doc.add_paragraph("- Admin panel exposed with default creds (test:test)")
doc.save("Pentest_Report.docx")
