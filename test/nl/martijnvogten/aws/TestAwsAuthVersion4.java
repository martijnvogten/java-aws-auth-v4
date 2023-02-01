package nl.martijnvogten.aws;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;

import org.junit.Assert;
import org.junit.Test;

import nl.martijnvogten.aws.AwsAuthVersion4.APIRequest;
import nl.martijnvogten.aws.AwsAuthVersion4.NameValue;
import nl.martijnvogten.aws.AwsAuthVersion4.SignedAPIRequest;

public class TestAwsAuthVersion4 {
	
	private static final String SECRET_KEY_TESTSUITE = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
	private static final String ACCESS_KEY_TESTSUITE = "AKIDEXAMPLE";

	@Test
	public void testAllAmazonTests() throws Exception {
		String[] files = {
			"get-header-key-duplicate",
			"get-header-value-order",
			"get-header-value-trim",
			"get-relative-relative",
			"get-relative",
			"get-slash-dot-slash",
			"get-slash-pointless-dot",
			"get-slash",
			"get-slashes",
			"get-space",
			"get-unreserved",
			"get-utf8",
			"get-vanilla-empty-query-key",
			"get-vanilla-query-order-key-case",
			"get-vanilla-query-order-key",
			"get-vanilla-query-order-value",
			"get-vanilla-query-unreserved",
			"get-vanilla-query",
			"get-vanilla-ut8-query",
			"get-vanilla",
			"post-header-key-case",
			"post-header-key-sort",
			"post-header-value-case",
			"post-vanilla-empty-query-value",
			"post-vanilla-query-nonunreserved",
			"post-vanilla-query-space",
			"post-vanilla-query",
			"post-vanilla",
			"post-x-www-form-urlencoded-parameters",
			"post-x-www-form-urlencoded",
		};
		for(String f : files) {
			System.out.println("Running " + f);
			runAmazonTest(f);
		}
	}
	
	public void runAmazonTest(String basename) throws Exception {
		String expected_string_to_sign = loadFile(basename + ".sts");
		String expected_canonical_request = loadFile(basename + ".creq");
		String expected_authz = loadFile(basename + ".authz");
		
		GregorianCalendar cal = new GregorianCalendar(2011, 8, 9, 23, 36, 0);
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		Date now = cal.getTime();
		
		APIRequest req = parseRequest(loadFile(basename + ".req"));
		
		List<String> headerNames = new ArrayList<>();
		for(NameValue h : req.getHeaders()) {
			headerNames.add(h.name);
		}
		
		String[] signed_headers = headerNames.toArray(new String[headerNames.size()]);
		
		Assert.assertEquals(expected_canonical_request, AwsAuthVersion4.buildCanonicalRequest(req, now, signed_headers));
		Assert.assertEquals(expected_string_to_sign, AwsAuthVersion4.buildStringToSign(req, expected_canonical_request, now));
		
		SignedAPIRequest signedRequest = AwsAuthVersion4.signRequest(req, signed_headers, ACCESS_KEY_TESTSUITE, SECRET_KEY_TESTSUITE, now);
		
		Assert.assertEquals(expected_authz, NameValue.findValue(signedRequest.headers, "Authorization"));
	}

	private static String loadFile(String file) throws IOException {
		URL resource = TestAwsAuthVersion4.class.getResource("authv4_testsuite/" + file);
		try {
			return new String(Files.readAllBytes(Paths.get(resource.toURI())), Charset.forName("utf-8")).replaceAll("\r", "");
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}
	
	private APIRequest parseRequest(String file) {
		try {
			String[] lines = file.split("\n");
			String[] headersBody = file.split("\n\n");
			String[] headerLines = headersBody[0].split("\n");
			List<NameValue> headers = new ArrayList<>();
			for(int i = 1; i < headerLines.length; i++) {
				String line = headerLines[i];
				int colonPos = line.indexOf(':');
				String headerName = headerLines[i].substring(0, colonPos); 
				String value = headerLines[i].substring(colonPos + 1); 
				headers.add(new NameValue(headerName, value));
			}
			String uri = lines[0].split("\\s+")[1];
			int qpos = uri.indexOf('?');
			String query = qpos > -1 ? uri.substring(qpos + 1) : "";
			String path = qpos > -1 ? uri.substring(0, qpos) : uri;
			String query_string = query == null ? "" : query;
			String payload = headersBody.length > 1 ? headersBody[1] : "";
			return new APIRequest() {
				
				@Override
				public String getPath() {
					return path;
				}
				
				@Override
				public String getService() {
					return "host";
				}
				
				@Override
				public String getRegion() {
					return "us-east-1";
				}
				
				@Override
				public String getPayload() {
					return payload;
				}
				
				@Override
				public String getQueryString() {
					return query_string;
				}
				
				@Override
				public String getMethod() {
					return lines[0].split("\\s+")[0];
				}
				
				@Override
				public List<NameValue> getHeaders() {
					return headers;
				}
			};
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
