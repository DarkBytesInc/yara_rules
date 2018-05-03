rule Win_Worm_Napsin_2
{
strings:
	$a0 = { 614802d3f1faa040d321b6271487c7bac665da14af4abf1989c520642c1ad6508384484dcc872324c7e0612af5061906d3cbdc6da28b0a7fbe10b521d98eb2b8bfabc1f2fd843bef6a8a769af4045c20fbd614bd2155ac591f9dbb35c4c7bb54 }

condition:
	$a0
}

        
