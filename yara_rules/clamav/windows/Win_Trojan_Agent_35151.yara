rule Win_Trojan_Agent_35151
{
strings:
	$a0 = { ffeb5672087ea3545b59d84a03b5def9d4c349225b7bab103947804f58ac4207117e5fcddb5f6edc68934e1fd39776071eb00fd3d9f6c1474a476291ef9849092d61a0b2ca0d9609744a4cfb1cad }

condition:
	$a0
}

        
