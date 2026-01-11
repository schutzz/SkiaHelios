
import yaml
import re
from pathlib import Path
from typing import Dict, Any, Optional, List

class NarrativeGenerator:
    """
    Narrator Engine for SkiaHelios (Lachesis).
    Converts structured IOC events into human-readable narratives using YAML templates.
    """
    def __init__(self, template_path: str):
        self.template_path = Path(template_path)
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, Any]:
        """Loads the YAML template file."""
        if not self.template_path.exists():
            print(f"    [!] Warning: Narrative template not found at {self.template_path}")
            return {}
        
        try:
            with open(self.template_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                # Supports both direct structure and nested 'templates' key
                return data.get("templates", data) 
        except Exception as e:
            print(f"    [!] Error loading narrative templates: {e}")
            return {}

    def _select_template_key(self, tags: str, category: str) -> Optional[str]:
        """
        Selects the best matching template key based on Tags and Category.
        Prioritizes specific tags over generic categories.
        """
        if not tags: tags = ""
        tag_list = [t.strip() for t in tags.split(",")]
        
        # 1. Direct Tag Match (e.g., CRITICAL_ADS_MASQUERADE)
        for tag in tag_list:
            # Check for exact match in templates
            if tag in self.templates:
                return tag
            # Check for close match? (optional)
        
        # 2. Tag Substring Match (e.g. TIMESTOMP in TIMESTOMP_FUTURE)
        # Iterate over template keys and check if they exist in tags
        # This is more expensive but allows "TIMESTOMP" template to catch "TIMESTOMP,GENERIC"
        # However, we only match if the template key is explicitly in the tags to avoid false positives.
        
        # 3. Known Patterns Handling (Fallback mapping if tags differ from template keys)
        # This allows mapping generic logic to specific templates if tag isn't exact
        if "ADS" in tags and "MASQUERADE" in tags: return "CRITICAL_ADS_MASQUERADE"
        if "TIMESTOMP" in tags: return "CRITICAL_NULL_TIMESTOMP" # Default timestomp
        if "WEBSHELL" in category.upper(): return "CRITICAL_WEBSHELL"
        
        return None

    def resolve(self, ioc: Dict[str, Any]) -> Optional[str]:
        """
        Generates the narrative string for a given IOC event.
        Returns None if no matching template is found.
        """
        tags = str(ioc.get("Tag", ""))
        category = str(ioc.get("Type", "")) # Renderer maps Category to ioc['Type'] usually
        
        key = self._select_template_key(tags, category)
        if not key or key not in self.templates:
            return None

        template_data = self.templates[key]
        fmt_str = template_data.get("template", "")
        title = template_data.get("title", "")
        rec = template_data.get("recommendation", "")
        
        # Prepare Context
        # Map IOC fields to template placeholders
        val = str(ioc.get("Value", "") or ioc.get("Target_Path", "") or ioc.get("FileName", "") or "Unknown")
        
        context = {
            "filename": val,
            "target": val,
            "timestamp": str(ioc.get("Time", "Unknown")),
            "score": str(ioc.get("Score", "")),
            "tag": tags,
            # Add other potential fields
            "decoded_str": str(ioc.get("Decoded", "N/A"))
        }

        try:
            # Safe rendering (handle missing keys gracefully not implemented in str.format, 
            # so using a dict that defaults to N/A is handled by logic/preparation)
            # For robustness, we check placeholders
            body = fmt_str.format(**context)
            
            # Construct Final Block
            # Format: 
            # ### Title
            # Body
            # > 💡 **Recommendation**: ...
            
            final_md = f"### {title}\n{body}"
            if rec:
                final_md += f"\n\n> 💡 **Recommendation**: {rec}"
                
            return final_md

        except KeyError as e:
            print(f"    [!] Template Error ({key}): Missing placeholder {e}")
            return f"### {title}\n(Error generating narrative: missing {e})\n{fmt_str}"
        except Exception as e:
            print(f"    [!] Narrative Gen Error: {e}")
            return None
