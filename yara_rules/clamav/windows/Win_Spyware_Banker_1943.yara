rule Win_Spyware_Banker_1943
{
strings:
	$a0 = { fd3dbc43386a237a6c871f81f9dd8618cdc8a7d3ece86ecc7f6dfc26b6f3063d7dfc884e2d5994a087d63f968f7b5c4271f21eebe7bb34c8688ec6a593c410dd43af89120ee8c319feb0ff60a14323c41bf97ddd8d136e59a38910da2b2a1fa611efcf0a435b046f5dfdc3cdef3617d18496bb }

condition:
	$a0
}

        
