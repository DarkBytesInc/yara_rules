rule Win_Adware_Lookme_39
{
strings:
	$a0 = { 4313e23ba24d89c6c3dfbd30bc8df1284d0fa20ef3fb7fa5cff08afc004f0649ea3cad6b41fa237d2b46047d1b31c05909282635cb7c0eff9eaca62176fc28ddab95e7818db3c0f44b1725cfbbef4b8756fee2fd6b7fa9259c913a3aa60fc4b63a89e545e3f77baddd1ddc149a88 }

condition:
	$a0
}

        
