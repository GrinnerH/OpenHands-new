import re
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class CodeBlock:
    type: str  # 'if', 'else if', 'else', 'for', 'while', 'do-while', 'function'
    start_line: int
    end_line: int
    name: Optional[str] = None  # For functions
    has_braces: bool = True

def calculate_indentation_diff(line1, line2):
    """
    Calculate the difference in indentation between two lines of code.
    
    Args:
        line1 (str): The first line of code
        line2 (str): The second line of code
    
    Returns:
        int: The difference in indentation (number of spaces or tabs)
    """
    # Count leading whitespace for each line
    indent1 = len(line1) - len(line1.lstrip())
    indent2 = len(line2) - len(line2.lstrip())
    
    # Return the absolute difference in indentation
    return indent1 - indent2

class CCodeAnalyzer:
    def __init__(self, source_code: str):
        self.lines = source_code.splitlines()
        self.blocks = []
        self.current_line = 0
        self.brace_stack = []

    def find_matching_brace(self, start_line: int) -> int:
        """Find the matching closing brace for an opening brace."""
        brace_count = 1
        for i in range(start_line+1, len(self.lines)):
            line = self.lines[i]

            lstrip_line = line.lstrip()
            if (lstrip_line.startswith('}') and brace_count == 1):
                return i
            
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0:
                return i
        return -1

    def find_next_statement_end(self, start_line: int) -> int:
        """Find the end of the next complete statement for braceless blocks."""
        if start_line >= len(self.lines):
            return start_line
    
        # Look for the next non-empty line
        ans = 0
        expression_first_line = 0
        for i in range(start_line + 1, len(self.lines)):
            line = self.lines[i].strip()
            if line and not line.startswith('//') and not line.startswith('/*'):
                ans = i
                expression_first_line = i
                break
        
        for i in range(expression_first_line+1, len(self.lines)):
            if calculate_indentation_diff(self.lines[expression_first_line], self.lines[i]) < 0:
                ans = i
            else:
                break
                
        return ans

    def analyze_functions(self):
        """Detect function declarations and their blocks."""
        func_pattern = re.compile(r'^(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*{')
        
        for i, line in enumerate(self.lines):
            match = func_pattern.search(line)
            if match and line.endswith('{'):
                func_name = match.group(1)
                end_line = self.find_matching_brace(i)
                if end_line != -1:
                    self.blocks.append(CodeBlock(
                        type='function',
                        start_line=i + 1,
                        end_line=end_line + 1,
                        name=func_name
                    ))

    def analyze_control_structures(self):
        """Detect if, else if, else blocks and loops, including those without braces."""
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()
            # Handle if/else if/else
            if line.startswith('if '):
                if line.endswith('{'):
                    end_line = self.find_matching_brace(i)
                    self.blocks.append(CodeBlock('if', i + 1, end_line + 1))
                    i += 1
                else:
                    end_line = self.find_next_statement_end(i)
                    self.blocks.append(CodeBlock('if', i + 1, end_line + 1, has_braces=False))
                    i += 1
                continue
                
            elif line.startswith('else if '):
                if line.endswith('{'):
                    end_line = self.find_matching_brace(i)
                    self.blocks.append(CodeBlock('else if', i + 1, end_line + 1))
                    i += 1
                else:
                    end_line = self.find_next_statement_end(i)
                    self.blocks.append(CodeBlock('else if', i + 1, end_line + 1, has_braces=False))
                    i += 1
                continue
                
            elif line.startswith('} else if '):
                if line.endswith('{'):
                    end_line = self.find_matching_brace(i)
                    self.blocks.append(CodeBlock('else if', i + 1, end_line + 1))
                    i += 1
                else:
                    end_line = self.find_next_statement_end(i)
                    self.blocks.append(CodeBlock('else if', i + 1, end_line + 1, has_braces=False))
                    i += 1
                continue
                
            elif line.startswith('else'):
                if line.endswith('{'):
                    end_line = self.find_matching_brace(i)
                    self.blocks.append(CodeBlock('else', i + 1, end_line + 1))
                    i += 1
                else:
                    end_line = self.find_next_statement_end(i)
                    self.blocks.append(CodeBlock('else', i + 1, end_line + 1, has_braces=False))
                    i += 1
                continue

            elif line.startswith('} else'):
                if line.endswith('{'):
                    end_line = self.find_matching_brace(i)
                    self.blocks.append(CodeBlock('else', i + 1, end_line + 1))
                    i += 1
                else:
                    end_line = self.find_next_statement_end(i)
                    self.blocks.append(CodeBlock('else', i + 1, end_line + 1, has_braces=False))
                    i += 1
                continue
            
            # Handle loops
            elif line.startswith('for '):
                if '{' in line:
                    end_line = self.find_matching_brace(i)
                    self.blocks.append(CodeBlock('for', i + 1, end_line + 1))
                    i += 1
                else:
                    end_line = self.find_next_statement_end(i)
                    self.blocks.append(CodeBlock('for', i + 1, end_line + 1, has_braces=False))
                    i += 1
                continue
                
            elif line.startswith('while '):
                if '{' in line:
                    end_line = self.find_matching_brace(i)
                    self.blocks.append(CodeBlock('while', i + 1, end_line + 1))
                    i += 1
                else:
                    end_line = self.find_next_statement_end(i)
                    self.blocks.append(CodeBlock('while', i + 1, end_line + 1, has_braces=False))
                    i += 1
                continue
                
            elif line.startswith('do'):
                # do-while always needs braces in C
                end_line = self.find_matching_brace(i)
                self.blocks.append(CodeBlock('do-while', i + 1, end_line + 1))
                i += 1
                continue
            
            i += 1

    def analyze(self) -> List[CodeBlock]:
        """Perform complete analysis of the source code."""
        self.analyze_functions()
        self.analyze_control_structures()
        return sorted(self.blocks, key=lambda x: x.start_line)

def analyze_c_code(source_code: str) -> List[CodeBlock]:
    """Main function to analyze C source code."""
    analyzer = CCodeAnalyzer(source_code)
    return analyzer.analyze()

# Example usage
if __name__ == "__main__":
    example_code = """
    int main(int argc, char *argv[]) {
        if (argc > 1)
            printf("Has arguments\\n");
        else if (argc == 1)
            printf("No arguments\\n");
        else
            printf("Error\\n");
        
        for (int i = 0; i < argc; i++)
            printf("%s\\n", argv[i]);
        
        // With braces
        if (argc > 2) {
            printf("Multiple arguments\\n");
            printf("First arg: %s\\n", argv[1]);
        }
        
        return 0;
    }
    """
    
    blocks = analyze_c_code(example_code)
    for block in blocks:
        print(f"{block.type}: lines {block.start_line}-{block.end_line}"
              f"{f' (function: {block.name})' if block.name else ''}"
              f"{' (no braces)' if not block.has_braces else ''}")
