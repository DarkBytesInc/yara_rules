rule Win_Spyware_Ardamax_26
{
strings:
	$a0 = { cb3a0d7053f77d4fd6b3fc0ccf968ce5201c810588c68e7cab3b91d6ae0891633f59093c23d7e8c305dbdc0accd3c15d6af45c6e431eece1cd7ffe796d6e4bb6ac47565873b7dcd2dd65b78ea56bd359164536b4a9c15c6a025b0d491313b9ab4b1c5b2486b7dfefff6403f95a775bef66787afff7fff87d7f3e29427f }

condition:
	$a0
}

        
