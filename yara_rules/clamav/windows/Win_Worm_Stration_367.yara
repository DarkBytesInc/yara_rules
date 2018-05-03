rule Win_Worm_Stration_367
{
strings:
	$a0 = { 6133abea57fe7cfc860d32deff0cdabe4546ba572d52fc81e3f1b7daa0d5d75b41d615344c0b4a0a6bd567c37321e636584a36c8b321f7c28a8eefa002dae3e5e8777eac064d291df6dc7577227030f9f5fe2dd28beedc4e74b4c2a41282f5d514dfd78c20383a45d8503d2e3840d6df }

condition:
	$a0
}

        
