/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "sipp-rpc.h"

bool_t
xdr_callcounter (XDR *xdrs, callcounter *objp)
{
	register int32_t *buf;


	if (xdrs->x_op == XDR_ENCODE) {
		buf = XDR_INLINE (xdrs, 4 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			 if (!xdr_int (xdrs, &objp->incomingcalls))
				 return FALSE;
			 if (!xdr_int (xdrs, &objp->outgoingcalls))
				 return FALSE;
			 if (!xdr_int (xdrs, &objp->successcalls))
				 return FALSE;
			 if (!xdr_int (xdrs, &objp->failurecalls))
				 return FALSE;
		} else {
			IXDR_PUT_LONG(buf, objp->incomingcalls);
			IXDR_PUT_LONG(buf, objp->outgoingcalls);
			IXDR_PUT_LONG(buf, objp->successcalls);
			IXDR_PUT_LONG(buf, objp->failurecalls);
		}
		return TRUE;
	} else if (xdrs->x_op == XDR_DECODE) {
		buf = XDR_INLINE (xdrs, 4 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			 if (!xdr_int (xdrs, &objp->incomingcalls))
				 return FALSE;
			 if (!xdr_int (xdrs, &objp->outgoingcalls))
				 return FALSE;
			 if (!xdr_int (xdrs, &objp->successcalls))
				 return FALSE;
			 if (!xdr_int (xdrs, &objp->failurecalls))
				 return FALSE;
		} else {
			objp->incomingcalls = IXDR_GET_LONG(buf);
			objp->outgoingcalls = IXDR_GET_LONG(buf);
			objp->successcalls = IXDR_GET_LONG(buf);
			objp->failurecalls = IXDR_GET_LONG(buf);
		}
	 return TRUE;
	}

	 if (!xdr_int (xdrs, &objp->incomingcalls))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->outgoingcalls))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->successcalls))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->failurecalls))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_callcounter_t (XDR *xdrs, callcounter_t *objp)
{
	register int32_t *buf;

	 if (!xdr_callcounter (xdrs, objp))
		 return FALSE;
	return TRUE;
}