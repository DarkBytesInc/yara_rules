rule Win_Trojan_SdBot_3925
{
strings:
	$a0 = { 9e41360a945d90fb2438bb4b8d9188195f9eb3c6d0ce35ba3ef8e5ae0c9be78e1a8b201abb260648baa5ae3e4fdea1e16b118d017c905d926333e0aca3a627b8df83de1706b75af7a56a30757d2af01e19433b7fd983cdfad137675c }

condition:
	$a0
}

        
