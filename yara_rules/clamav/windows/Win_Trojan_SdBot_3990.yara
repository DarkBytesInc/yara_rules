rule Win_Trojan_SdBot_3990
{
strings:
	$a0 = { 193778711024e0db99795bb6753e3c366a0f728f09b99302482501c3b32e53c7d06d6830192fe53fb214b5167eed1d6bf3eda6bd66ad4c6520f90092eb064a6a75a3d719b8533d7f04ef94d505f9a38cc7696da69f899d5d0210303eaeb3ed70efd2f17cc5476576ac6ddde255d09a3173b0139c4e8d2a081da6edb9e862c6ae }

condition:
	$a0
}

        