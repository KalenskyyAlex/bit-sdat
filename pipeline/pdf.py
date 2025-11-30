import json
from . import IocReport, Pipeline
import io
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import matplotlib.pyplot as plt
from collections import defaultdict

class GeneratePdfPipeline(Pipeline):
    def __init__(self, output, filename = None, content = None):
        if not filename and not content:
            raise ValueError('Provide either filename or content')
        
        if filename and content:
            raise ValueError('Provide either filename or content')
        
        self.filename = filename
        self.output = output
        self.content = content
    
    def snake_to_friendly(self, snake_str: str) -> str:
        if not snake_str:
            return ''
        words = snake_str.split('_')
        # Capitalize first word, lowercase the rest
        return ' '.join([words[0].capitalize()] + [w.lower() for w in words[1:]])
    
    def run(self) -> IocReport:
        if self.filename:
            with open(self.filename, 'r') as f:
                self.content = IocReport.from_dict(json.load(f))
                
        doc = SimpleDocTemplate(str(self.output), pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()

        # --- Title ---
        elements.append(Paragraph("Analysis Report", styles['Title']))
        elements.append(Paragraph(str(self.output.resolve()), styles['Heading4']))
        elements.append(Spacer(1, 12))

        # --- Summary ---
        summary_text = f"""
        Verdict: <b>{self.snake_to_friendly(self.content.verdict)}</b><br/>
        Total Score: <b>{self.content.total_score:.2f}</b><br/>
        Total Hits: <b>{sum(hit.hits for hit in self.content.hits)}</b>
        """

        # --- Pie chart by category (name) ---
        category_counts = defaultdict(int)
        for hit in self.content.hits:
            category_counts[self.snake_to_friendly(hit.name)] += hit.hits

        labels = list(category_counts.keys())
        sizes = list(category_counts.values())

        # Generate pie chart
        fig, ax = plt.subplots(figsize=(3,4))
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        ax.axis('equal')  # Equal aspect ratio

        # Save chart to a bytes buffer
        buf = io.BytesIO()
        plt.savefig(buf, format='PNG', bbox_inches='tight')
        buf.seek(0)
        plt.close(fig)

        # --- Put them side by side using a Table ---
        side_by_side_table = Table([[
            Paragraph(summary_text, styles['Heading2']), 
            Image(buf, width=300, height=300
        )]], colWidths=[150, 250])
        side_by_side_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('ALIGN',(1,1),(-1,-1),'LEFT'),
        ]))

        elements.append(side_by_side_table)
        elements.append(Spacer(1, 20))  # optional spacing below

        # --- Table of hits ---
        table_data = [['Name', 'Score', 'Hits', 'Description']]
        for hit in self.content.hits:
            table_data.append([
                self.snake_to_friendly(hit.name), 
                str(hit.score), 
                str(hit.hits), 
                Paragraph(hit.description, styles['BodyText']) 
            ])

        table = Table(table_data, colWidths=[100, 50, 50, 250])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('ALIGN',(1,1),(-1,-1),'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('VALIGN', (0, 1), (-1, -1), 'TOP'), 
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ]))
        elements.append(table)

        # --- Build PDF ---
        doc.build(elements)

