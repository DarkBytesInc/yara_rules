rule Win_Adware_Virtumonde_14
{
strings:
	$a0 = { bd302e08458a369fe15ab95fcf3e8b5ff1359204b98c4a19743eb8334c2119146481c4abeedd9e7c2c5a601265151ba102ddf82b272d3c4c2d45a4c9e47ec382f0296e07468dcee4aba385ae31c67974 }

condition:
	$a0
}

        
