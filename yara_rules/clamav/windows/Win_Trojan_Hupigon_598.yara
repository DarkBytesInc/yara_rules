rule Win_Trojan_Hupigon_598
{
strings:
	$a0 = { 113e437390ffc36723d42aaa4388672679c2a3e710a6b5f9d63012d26afaa89b4b61a79b25223c5382fce8746de46f4fa9868af4dfae5971180a043eec6c6316b3c600f76e0235e782c9d0f820b58e6a619b630c3deb0bb67b5d20c58ca0ead2c5af7e6703c2c561b64a82ca3af9206384ec608fde03e5882acfc933dfdc9c6ab6c5d95edf1c }

condition:
	$a0
}

        