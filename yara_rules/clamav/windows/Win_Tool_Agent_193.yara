rule Win_Tool_Agent_193
{
strings:
	$a0 = { 7f2a06b8024ab704cd2f47bb06007408e89200f3a4e89e001f433179fc75fab40dcd2153911eb8403d8d17cd210e93 }

condition:
	$a0
}

        
