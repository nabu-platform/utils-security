package be.nabu.utils.security;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

public enum ECType {
	EC256("p-256", "nistp256"),
	EC384("p-384", "nistp384"),
	EC521("p-521", "nistp521")
	;
	private String curveName;
	private String nistName;

	private ECType(String nistName, String curveName) {
		this.nistName = nistName;
		// can occur in some formats and be used to validate, currently not used
		this.curveName = curveName;
	}

	public String getCurveName() {
		return curveName;
	}
	public void setCurveName(String curveName) {
		this.curveName = curveName;
	}

	public String getNistName() {
		return nistName;
	}
	public void setNistName(String nistName) {
		this.nistName = nistName;
	}
	
	public X9ECParameters getECParameters() {
		return NISTNamedCurves.getByName(nistName);
	}
	
	public ECNamedCurveSpec getECSpecification() {
		X9ECParameters ecParameters = getECParameters();
        return new ECNamedCurveSpec(nistName, ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN());
	}
}
