package nl.martijnvogten.aws;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AwsAuthVersion4 {
	
	private static final String NEWLINE = "\n";
	private static final String ALGORITHM = "AWS4-HMAC-SHA256";
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	private static final Charset UTF_8 = Charset.forName("utf-8");

	public interface APIRequest {
		public String getService();
		public String getRegion();
		
		public String getMethod();
		public String getPath();
		public String getQueryString();
		public List<NameValue> getHeaders();
		public String getPayload();
	}
	
	public static class NameValue {
		public final String name;
		public final String value;

		public NameValue(String name, String value) {
			this.name = name;
			this.value = value;
		}
		
		public static String findValue(List<NameValue> headers, String headerName) {
			for(NameValue h : headers) {
				if (h.name.equals(headerName)) {
					return h.value;
				}
			}
			return null;
		}
	}
	
	public static class SignedAPIRequest {
		String method;
		List<NameValue> headers;
		String payload;
	}

	public static SignedAPIRequest signRequest(APIRequest req, String[] signed_headers, String access_key, String secret_key, Date now) throws Exception {
		
		String canonical_request = buildCanonicalRequest(req, now, signed_headers);
		String credential_scope = buildCredentialScope(req, now);
		String string_to_sign = buildStringToSign(req, canonical_request, now);
		
		byte[] signing_key = getSignatureKey(secret_key, getDateStamp(now), req.getRegion(), req.getService());
		String signature = toHex(sign(signing_key, string_to_sign));
		
		String authorization_header = ALGORITHM + " " + "Credential=" + access_key + "/" + credential_scope + ", " + "SignedHeaders=" + join(";", cleanHeaders(signed_headers)) + ", " + "Signature=" + signature;

		List<NameValue> headers = new ArrayList<>(req.getHeaders());
		headers.add(new NameValue("Authorization", authorization_header));
	
		SignedAPIRequest result = new SignedAPIRequest();
		result.method = req.getMethod();
		result.payload = req.getPayload();
		result.headers = headers;
		return result;
	}
	
	public static String buildCredentialScope(APIRequest req, Date now) {
		return getDateStamp(now) + "/" + req.getRegion() + "/" + req.getService()+ "/" + "aws4_request";
	}
	
	public static String buildStringToSign(APIRequest req, String canonical_request, Date now) throws NoSuchAlgorithmException {
		return ALGORITHM + NEWLINE + getDateTimeStamp(now) + NEWLINE + buildCredentialScope(req, now) + NEWLINE + hash(canonical_request);
	}

	public static String buildCanonicalRequest(APIRequest req, Date now, String[] signed_headers) throws NoSuchAlgorithmException, IOException {
		try {
			String path = new URI(req.getPath().replaceAll("\\/+",  "/")).normalize().getPath();
			Iterable<String> parts = split("/", path);
			List<String> encParts = new ArrayList<>();
			for (String p : parts) {
				encParts.add(urlEncode(p));
			}
			String canonical_uri = join("/", encParts);
			
			String canonical_querystring = cleanQueryString(req.getQueryString());

			List<String> sortedHeaders = cleanHeaders(signed_headers);
			
			StringBuilder header_list = new StringBuilder();
			for(String header : sortedHeaders) {
				if (header_list.length() > 0) {
					header_list.append(";");
				}
				header_list.append(header);
			}
				
			StringBuilder canonical_headers = new StringBuilder();
			
			for(String header : sortedHeaders) {
				List<String> headerValue = new ArrayList<>(); 

				canonical_headers.append(header.toLowerCase());
				canonical_headers.append(":");
				for(NameValue originalHeader : req.getHeaders()) {
					if (originalHeader.name.toLowerCase().equals(header)) {
						headerValue.add(originalHeader.value.trim());
					}
				}
				
				if (headerValue.size() == 0) {
					throw new RuntimeException("Header " + header + " not present in request");
				}
				Collections.sort(headerValue);
				canonical_headers.append(join(",", headerValue));
				canonical_headers.append(NEWLINE);
			}
			
			String payload_hash = hash(req.getPayload());
		
			String canonical_request = req.getMethod() + NEWLINE
				+ canonical_uri + NEWLINE
				+ canonical_querystring + NEWLINE
				+ canonical_headers + NEWLINE
				+ join(";", sortedHeaders) + NEWLINE
				+ payload_hash;
			
			return canonical_request;
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * String join that also works with empty strings
	 * 
	 * @param glue
	 * @param parts
	 * @return joined string
	 */
	private static String join(String glue, List<String> parts) {
		StringBuilder result = new StringBuilder();
		boolean addSeparator = false;
		for(String p : parts) {
			if(addSeparator) {
				result.append(glue);
			}
			result.append(p);
			addSeparator = true;
		}
		return result.toString();
	}

	/**
	 * Also adds empty strings where String.split doesn't
	 * 
	 * @param regex Regular expression to split by
	 * @param whole The string to split
	 * @return pieces
	 */
	private static Iterable<String> split(String regex, String whole) {
		Pattern p = Pattern.compile(regex);
		Matcher m = p.matcher(whole);
		List<String> result = new ArrayList<>();
		int pos = 0;
		while(m.find()) {
			result.add(whole.substring(pos, m.start()));
			pos = m.end();
		}
		result.add(whole.substring(pos));
		return result;
	}
	
	private static List<NameValue> splitQuery(String queryString) {
		if (queryString.length() == 0) {
			return Collections.emptyList();
		}
		final String[] parts = queryString.split("&");
		List<NameValue> result = new ArrayList<>();
		for (String p : parts) {
			int idx = p.indexOf("=");
			String key = idx > -1 ? urlDecode(p.substring(0, idx)) : p;
			result.add(new NameValue(key, idx > -1 ? urlDecode(p.substring(idx + 1)) : ""));
		}
		return result;
	}
	
	private static String urlDecode(String str) {
		try {
			return URLDecoder.decode(str, UTF_8.name());
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	private static String urlEncode(String str) {
		try {
			return URLEncoder.encode(str, UTF_8.name())
				.replaceAll("\\+", "%20")
				.replaceAll("%7E", "~");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	private static String cleanQueryString(String queryString) {
		List<NameValue> params = splitQuery(queryString);
		
		// Sort by name, then by value
		Collections.sort(params, new Comparator<NameValue>() {
			@Override
			public int compare(NameValue o1, NameValue o2) {
				return o1.name.equals(o2.name) ? o1.value.compareTo(o2.value) : o1.name.compareTo(o2.name);
			}});
		
		StringBuilder result = new StringBuilder();
		for (NameValue p : params) {
			if (result.length() > 0) {
				result.append("&");
			}
			result.append(urlEncode(p.name));
			result.append('=');
			result.append(urlEncode(p.value));
		}
		return result.toString();
	}
	
	private static List<String> cleanHeaders(String[] signed_headers) {
		List<String> sortedHeaders = new ArrayList<>();
		for (String header : signed_headers) {
			if (!sortedHeaders.contains(header.toLowerCase())) {
				sortedHeaders.add(header.toLowerCase());
			}
		}
		Collections.sort(sortedHeaders);
		return sortedHeaders;
	}
	
	private static String getDateStamp(Date time) {
		SimpleDateFormat dateFmt = new SimpleDateFormat("yyyyMMdd", Locale.ENGLISH);
		dateFmt.setTimeZone(TimeZone.getTimeZone("UTC"));
		return dateFmt.format(time);
	}
	
	private static String getDateTimeStamp(Date time) {
		SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.ENGLISH);
		fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
		return fmt.format(time);
	}
	
	private static String hash(String payload) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(payload.getBytes(UTF_8));
		return String.format("%064x", new java.math.BigInteger(1, md.digest()));
	}
	
	private static byte[] sign(byte[] key, String msg) {
		try {
			SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA256_ALGORITHM);
			Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
			mac.init(signingKey);
			return mac.doFinal(msg.getBytes(UTF_8));
		} catch (GeneralSecurityException gse) {
			throw new RuntimeException(gse);
		}
	}

	private static String toHex(byte[] bytes) {
		return String.format("%064x", new java.math.BigInteger(1, bytes));
	}

	private static byte[] getSignatureKey(String key, String date_stamp, String regionName, String serviceName) {
		byte[] kDate = sign(("AWS4" + key).getBytes(UTF_8), date_stamp);
		byte[] kRegion = sign(kDate, regionName);
		byte[] kService = sign(kRegion, serviceName);
		byte[] kSigning = sign(kService, "aws4_request");
		return kSigning;
	}

}
