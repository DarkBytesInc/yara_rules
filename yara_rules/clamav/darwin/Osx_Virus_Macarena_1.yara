rule Osx_Virus_Macarena_1
{
strings:
	$a0 = { 5e5b[0-5]d04d6163686f4d616e202d20726f79206720626976[0-10]56506a4958cd805350b006cd80c9c3[0-5]2f31302f30366a }

condition:
	$a0
}

        
