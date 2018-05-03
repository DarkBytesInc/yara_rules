rule Win_Proxy_Lager_58
{
strings:
	$a0 = { ad46ce1fe217ee6b4e0be809417d40f1421700a3d094d8ee52f3ed2692ade00839abe5765097ea6e2754374a2c2f97b3534cc7fe164ae811a5c0919ec9b9878b527bb700a01a }

condition:
	$a0
}

        
