rule Win_Spyware_Banker_2419
{
strings:
	$a0 = { 68d58e76fc50a9f3739f81d068331af1c963d5c5faf9c04a94de601d4ce5d72396b176c0af8303f888c0927f46f56d3b54bb5cd129abfac7dd8990e00e6b214b2ee286cbabaed6a2bdd9787fcd75d9f48759247ed7e005abef6f37343bc21c837ed4dae6f09d }

condition:
	$a0
}

        
