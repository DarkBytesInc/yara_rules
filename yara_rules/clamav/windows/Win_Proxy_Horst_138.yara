rule Win_Proxy_Horst_138
{
strings:
	$a0 = { e67477726d6a684dd35c9a6663737a797675344dd3346b6967656134cda5b972756f70797473ce344dd3726c6b682b4dd3749b706e7a03706f6c639aa6692e6d7978777675699aa669746e6b6864d33497a663616c797675 }

condition:
	$a0
}

        