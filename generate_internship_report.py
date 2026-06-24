import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, PageBreak
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.lib.utils import ImageReader

def create_report():
    output_path = "Internship_Project_Report.pdf"
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY, parent=styles['Normal'], spaceAfter=10))
    styles.add(ParagraphStyle(name='CenterTitle', alignment=TA_CENTER, parent=styles['Title'], spaceAfter=20))
    
    Story = []
    
    # Title
    Story.append(Paragraph("Internship Project Report: Project Shield", styles['CenterTitle']))
    Story.append(Paragraph("CFSS Global Internship 2026", styles['Heading3']))
    Story.append(Spacer(1, 1*cm))
    
    # Executive Summary
    Story.append(Paragraph("1. Executive Summary", styles['Heading2']))
    Story.append(Paragraph(
        "Project Shield is a full-stack, AI-powered security analytics dashboard developed during the CFSS Global Internship 2026. "
        "The primary goal was to build a system capable of ingesting security logs, analyzing them using Machine Learning models "
        "(such as Isolation Forest and Random Forest), and providing actionable threat intelligence through an intuitive UI. "
        "This project successfully bridged the gap between raw data and actionable security insights, demonstrating end-to-end "
        "software development and data science capabilities.", styles['Justify']))
    
    # Methodology & Tools
    Story.append(Paragraph("2. Methodology", styles['Heading2']))
    Story.append(Paragraph(
        "The project followed an agile methodology spanning four weeks. Week 1 focused on system architecture and data engineering, "
        "establishing the database schema and preprocessing NSL-KDD inspired datasets. Week 2 involved training Machine Learning models "
        "for anomaly detection and building the Python/Flask backend. Week 3 integrated the frontend with the backend, "
        "securing APIs with JWT and ensuring protection against OWASP Top 10 vulnerabilities. Finally, Week 4 involved deploying the "
        "application to Render and finalizing documentation.", styles['Justify']))
    Story.append(Paragraph("Key Tools Applied:", styles['Heading3']))
    Story.append(Paragraph(
        "- Backend: Python, Flask, Flask-JWT-Extended<br/>"
        "- Frontend: HTML, CSS, JavaScript (Vanilla), Chart.js<br/>"
        "- AI/ML: Scikit-learn (Isolation Forest, Random Forest), Pandas, NumPy<br/>"
        "- Deployment: Render (Backend), Vercel (Frontend), GitHub", styles['Justify']))
    
    # Technical Findings & Contributions
    Story.append(Paragraph("3. Technical Findings & Key Contributions", styles['Heading2']))
    Story.append(Paragraph(
        "- Engineered a robust ingestion pipeline for CSV and JSON security logs.<br/>"
        "- Trained and implemented a multi-stage AI engine utilizing an Isolation Forest for rapid anomaly detection and a Random Forest for multi-class threat categorization.<br/>"
        "- Designed an interactive, dark-themed 'Cyber Investigator' dashboard capable of rendering dynamic charts and live threat feeds.<br/>"
        "- Implemented secure JWT-based authentication and role-based access control.", styles['Justify']))
    
    # Challenges & Solutions
    Story.append(Paragraph("4. Challenges & Innovative Solutions", styles['Heading2']))
    Story.append(Paragraph(
        "A major challenge was ensuring that the frontend seamlessly communicated with the backend in a deployed environment without "
        "triggering Mixed Content or CORS errors. This was resolved by dynamically configuring the API base URL based on the environment "
        "(localhost vs. production). Additionally, to make the dashboard visually impactful without heavy framework dependencies, "
        "vanilla CSS and JS were utilized with custom canvas-based particle animations, ensuring high performance and a premium user experience.", styles['Justify']))
    
    # Recommendations & Insights
    Story.append(Paragraph("5. Recommendations & Insights Gained", styles['Heading2']))
    Story.append(Paragraph(
        "Working on Project Shield provided profound insights into the intersection of cybersecurity and machine learning. "
        "One key realization is the importance of interpretability in security models—security analysts need a 'threat score' they can understand. "
        "Future recommendations for this system include integrating a real-time SIEM connector and exploring Deep Learning (e.g., LSTMs) "
        "for time-series log analysis.", styles['Justify']))
    
    Story.append(PageBreak())
    
    # Screenshots
    Story.append(Paragraph("6. Project Screenshots", styles['Heading2']))
    Story.append(Paragraph("The following screenshots demonstrate the core functionalities and UI of Project Shield, backing up the technical implementation with evidence.", styles['Justify']))
    Story.append(Spacer(1, 0.5*cm))

    screenshots_dir = "screenshots"
    if os.path.exists(screenshots_dir):
        images = sorted([f for f in os.listdir(screenshots_dir) if f.endswith('.png')])
        for img in images:
            img_path = os.path.join(screenshots_dir, img)
            # Add image to story
            try:
                img_reader = ImageReader(img_path)
                w, h = img_reader.getSize()
                aspect = h / float(w)
                rw = 15 * cm
                rh = rw * aspect
                
                # If height is too big, scale down to fit on page
                if rh > 20 * cm:
                    rh = 20 * cm
                    rw = rh / aspect

                Story.append(Paragraph(f"<b>Screenshot:</b> {img.replace('_', ' ').replace('.png', '')}", styles['Normal']))
                Story.append(Spacer(1, 0.2*cm))
                report_img = RLImage(img_path, width=rw, height=rh)
                Story.append(report_img)
                Story.append(Spacer(1, 0.8*cm))
            except Exception as e:
                Story.append(Paragraph(f"[Could not load image: {e}]", styles['Normal']))
    else:
        Story.append(Paragraph("No screenshots folder found.", styles['Normal']))

    doc.build(Story)
    print("Report generated successfully: " + output_path)

if __name__ == "__main__":
    create_report()
