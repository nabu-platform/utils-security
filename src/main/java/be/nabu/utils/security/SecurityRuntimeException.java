package be.nabu.utils.security;

public class SecurityRuntimeException extends RuntimeException {

	private static final long serialVersionUID = -4520663334067552102L;

	public SecurityRuntimeException() {
		super();
	}

	public SecurityRuntimeException(String arg0, Throwable arg1, boolean arg2, boolean arg3) {
		super(arg0, arg1, arg2, arg3);
	}

	public SecurityRuntimeException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}

	public SecurityRuntimeException(String arg0) {
		super(arg0);
	}

	public SecurityRuntimeException(Throwable arg0) {
		super(arg0);
	}

}
