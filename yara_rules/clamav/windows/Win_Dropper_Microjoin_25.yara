rule Win_Dropper_Microjoin_25
{
strings:
	$a0 = { eb156d505357f692f78801b32410c4a8d43edbe70c8ad3155fdb41ccd610416140fb9210482805a2091be22bd824afdab5d8d087dbc63be96aa7b4d37676ba3f98a943c1769dadae74b6bef011643a5d0547a5b5bb4b65a61b9a6ea5502cecc2de3d0f9d9d1dffedbffdb13739f77cdef371dfb9f71ef4065abc02b70d }

condition:
	$a0
}

        
