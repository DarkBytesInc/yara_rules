rule Win_Worm_Sumom_1
{
strings:
	$a0 = { 6336dd689fe2fa1b07cfb3e37fd5bec773f5fa4a1bf194dc2f220bf0dac59438f9a08f013b4a26dc4a7e9f518b1f59615d2b47fd3c5164329874dba0f994ac36749531dd4b8208df17dc46f14fbe51a99cb3804db3f58b743d3407f4b187f728 }

condition:
	$a0
}

        
