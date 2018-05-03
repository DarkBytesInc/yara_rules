rule Win_Tool_MemTrace_1
{
strings:
	$a0 = { 6601cd21b82135cd21530658e82800b83a0ecd1058e81f00e87e00b409ba7d01cd21a19a01e80f00b83a0ecd10 }

condition:
	$a0
}

        
