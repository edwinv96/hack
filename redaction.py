import cv2
import numpy as np
import pytesseract
from PIL import Image, ImageDraw
import fitz  # PyMuPDF
import re
import os

class RedactionTool:
    def __init__(self):
        # Common PII patterns
        self.patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
            'phone': r'\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b|\b\d{10}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'address': r'\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl)\b',
            'date': r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b',
            'name': r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'  # Simple name pattern
        }
    
    def detect_text_regions(self, image):
        """Detect text regions in an image using OCR"""
        try:
            # Convert PIL image to OpenCV format if needed
            if isinstance(image, Image.Image):
                image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            
            # Get bounding boxes for all text
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            
            text_regions = []
            n_boxes = len(data['level'])
            
            for i in range(n_boxes):
                if int(data['conf'][i]) > 30:  # Confidence threshold
                    text = data['text'][i].strip()
                    if text:
                        x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                        text_regions.append({
                            'text': text,
                            'bbox': (x, y, x + w, y + h),
                            'confidence': data['conf'][i]
                        })
            
            return text_regions
        except Exception as e:
            print(f"Error in text detection: {e}")
            return []
    
    def should_redact_text(self, text, methods):
        """Check if text should be redacted based on selected methods"""
        text_lower = text.lower()
        
        for method in methods:
            if method in self.patterns:
                if re.search(self.patterns[method], text, re.IGNORECASE):
                    return True
            elif method == 'all_text':
                return True
            elif method == 'numbers':
                if re.search(r'\d+', text):
                    return True
            elif method == 'names' and len(text.split()) >= 2:
                # Simple heuristic for names
                words = text.split()
                if all(word[0].isupper() and word[1:].islower() for word in words if len(word) > 1):
                    return True
        
        return False
    
    def redact_image(self, input_path, output_path, methods=['all_text']):
        """Redact sensitive information from images"""
        try:
            # Load image
            image = Image.open(input_path)
            
            # Detect text regions
            text_regions = self.detect_text_regions(image)
            
            # Create drawing context
            draw = ImageDraw.Draw(image)
            
            # Redact matching text
            for region in text_regions:
                if self.should_redact_text(region['text'], methods):
                    bbox = region['bbox']
                    # Draw black rectangle over text
                    draw.rectangle(bbox, fill='black')
            
            # Save redacted image
            image.save(output_path)
            print(f"Image redacted and saved to: {output_path}")
            
        except Exception as e:
            print(f"Error redacting image: {e}")
            # If redaction fails, copy original file
            import shutil
            shutil.copy2(input_path, output_path)
    
    def redact_pdf(self, input_path, output_path, methods=['all_text']):
        """Redact sensitive information from PDFs"""
        try:
            # Open PDF
            doc = fitz.open(input_path)
            
            for page_num in range(len(doc)):
                page = doc[page_num]
                
                # Get text with coordinates
                text_instances = page.get_text("dict")
                
                for block in text_instances["blocks"]:
                    if "lines" in block:
                        for line in block["lines"]:
                            for span in line["spans"]:
                                text = span["text"]
                                if self.should_redact_text(text, methods):
                                    # Get bounding box
                                    bbox = span["bbox"]
                                    rect = fitz.Rect(bbox)
                                    
                                    # Add redaction annotation
                                    redact_annot = page.add_redact_annot(rect)
                                    redact_annot.set_colors(stroke=[0, 0, 0], fill=[0, 0, 0])
                
                # Apply redactions
                page.apply_redactions()
            
            # Save redacted PDF
            doc.save(output_path)
            doc.close()
            print(f"PDF redacted and saved to: {output_path}")
            
        except Exception as e:
            print(f"Error redacting PDF: {e}")
            # If redaction fails, copy original file
            import shutil
            shutil.copy2(input_path, output_path)

# Example usage
if __name__ == "__main__":
    tool = RedactionTool()
    
    # Test image redaction
    # tool.redact_image("test_image.jpg", "redacted_image.jpg", methods=['ssn', 'phone', 'email'])
    
    # Test PDF redaction
    # tool.redact_pdf("test_document.pdf", "redacted_document.pdf", methods=['ssn', 'phone'])