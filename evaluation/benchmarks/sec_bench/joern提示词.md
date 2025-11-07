Instruction:
Your task is to design Precise Joern CPGQL Queries for
Vulnerability Analysis.
Objective:
Develop targeted CPGQL Joern queries to:
• Identify taint flows based on your analysis.
• Capture potential vulnerability paths.
Constraints:
• Queries must be executable in Joern/CPGQL
• Use Scala language features for query construction
• Last query must use reachableByFlows to identify
vulnerable paths
Output Requirements:
Provide a JSON object with one field "queries": Sequence
of CPGQL queries to detect vulnerability
Expected JSON Output Format:
{
"queries": ["Query1" , "Query2", ..., "Final
Reachable Flows Query"]
}
Example Output:
Example in Figure 9
Input: <Code>
