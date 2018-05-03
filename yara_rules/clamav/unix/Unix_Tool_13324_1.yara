rule Unix_Tool_13324_1
{
strings:
	$a0 = { 31c031db31c931d2eb325bb00531c9cd8089c6eb06b00131dbcd8089f3b00383ec018d0c24b201cd8031db39c374e6b004b301b201cd8083c401ebdfe8c9ffffff }

condition:
	$a0
}

        
