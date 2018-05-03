rule Win_Worm_Stration_331
{
strings:
	$a0 = { dab6ba875291704c55957da4643facfecef7e6782d503532e243c785c06d76c4153b52f883f8e97a83bb0fbdab434b7cf29ce19a8c76ed82bdec9c05376d37 }

condition:
	$a0
}

        
