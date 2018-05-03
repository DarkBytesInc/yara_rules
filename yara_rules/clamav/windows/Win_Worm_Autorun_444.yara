rule Win_Worm_Autorun_444
{
strings:
	$a0 = { 5b6175746f72756e0d0a3b4d4b6473616b4b4c3a4653446b66646c3b6b664b45466666736665fbcec0d4dbc0f8eef4fbe46a66ebe0f4fbe4e6ebe0d4c6c0ebeed3d9c6c0cbd4d3d3ced4c0f8eef3c6e0ebd4d3c6e0ebf4f36b6c7365cad4d7cbd1c4eaf4f1e4eef4eabcefe5eef7ca3f6b6c3f66534c6b666164653f464a4549 }

condition:
	$a0
}

        
