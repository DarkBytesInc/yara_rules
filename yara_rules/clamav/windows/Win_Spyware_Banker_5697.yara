rule Win_Spyware_Banker_5697
{
strings:
	$a0 = { a2da3deee875dbc9518cf0c3efbaf9acdf28516782dd910aca069e6a731c76ed8c7195048428be8bab754eb16950965cbd7e139ea8fe4f19320aff4ea1dc6c0ebe5e92b56db1097a0a381569ee459ffcb2e8cc5042991838b67f }

condition:
	$a0
}

        
