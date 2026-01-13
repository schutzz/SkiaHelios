
import sys
import os
sys.path.append(os.getcwd())

from tools.lachesis.analyzer import LachesisAnalyzer
from tools.lachesis.renderer import LachesisRenderer

# Mock Intel Module
class MockIntel:
    def __init__(self):
        self.noise_stats = {}
        self.context_scoring = {'path_penalties': []}
    def get(self, key, default=None):
        if key == 'context_scoring': return self.context_scoring
        return default

# Mock Enricher
class MockEnricher:
    pass

def test_noise_filter():
    analyzer = LachesisAnalyzer(MockIntel(), MockEnricher())
    
    # Failing Pattern from Report
    # | EXECUTION | `.\program files\windowsapps\deletedalluserpackages\microsoft.windowsmaps_5.1711.10401.0_neutral_split.scale-125_8wekyb3d8bbwe\assets\secondarytiles\collections\contrast-white\widetile.scale-125_contrast-white.png` | 300 | A,C,D,E,F,G,I,L,M,N,O,R,S,T,Y,_ |

    bad_ioc = {
        "Value": r".\program files\windowsapps\deletedalluserpackages\microsoft.windowsmaps_5.1711.10401.0_neutral_split.scale-125_8wekyb3d8bbwe\assets\secondarytiles\collections\contrast-white\widetile.scale-125_contrast-white.png",
        "Score": 300,
        "Tag": "A,C,D,E,F,G,I,L,M,N,O,R,S,T,Y,_"
    }
    
    print(f"Analyzer File: {sys.modules['tools.lachesis.analyzer'].__file__}")
    import inspect
    print(f"Source: {inspect.getsource(analyzer._is_noise)}")
    
    print(f"Testing IOC: {bad_ioc['Value']}")
    is_noise = analyzer._is_noise(bad_ioc)
    print(f"Result: {is_noise}")
    
    if is_noise:
        print("SUCCESS: Noise detected.")
    else:
        print("FAILURE: Noise passed through.")
        
        # Debugging why
        path = str(bad_ioc.get("Path", "") or bad_ioc.get("Value", "")).lower()
        norm_path = path.replace("/", "\\").replace(".\\", "").replace("\\\\", "\\")
        print(f"Norm Path: '{norm_path}'")
        
        garbage_patterns = [
            r"windows\winsxs", 
            r"windows\assembly", 
            r"windows\microsoft.net", 
            r"windows\servicing",
            r"windows\systemapps",
            r"windows\inf",
            r"windows\driverstore",
            r"windows\diagtrack",
            r"windows\biometry",
            r"windows\softwaredistribution",
            r"program files\windowsapps", # This should match
            r"deletedalluserpackages",
            r"\apprepository",
            r"\contentdeliverymanager",
            r"\infusedapps"
        ]
        
        for gp in garbage_patterns:
            if gp in norm_path:
                print(f"Matched garbage pattern manually: {gp}")
            else:
                 pass # print(f" Did not match: {gp}")

if __name__ == "__main__":
    test_noise_filter()
