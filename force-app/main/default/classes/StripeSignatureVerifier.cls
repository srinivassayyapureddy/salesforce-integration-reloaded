public class StripeSignatureVerifier {
    private static final String SIGNATURE_HEADER = 'Stripe-Signature';
    private static final String ALGORITHM = 'HmacSHA256';
    
    public Boolean isRequestValid(Map<String, String> headers, String payload, String webhookSecret) {
        String stripeSignature = headers.get(SIGNATURE_HEADER);
        if (stripeSignature == null) {
            return false;
        }
        
        try {
            // Parse Stripe signature format: t=timestamp,v1=signature
            Map<String, String> signatureParts = parseStripeSignature(stripeSignature);
            String timestamp = signatureParts.get('t');
            String expectedSignature = signatureParts.get('v1');
            
            if (timestamp == null || expectedSignature == null) {
                return false;
            }
            
            // Create signed payload: timestamp + '.' + payload
            String signedPayload = timestamp + '.' + payload;
            
            // Generate HMAC signature
            Blob secretBlob = Blob.valueOf(webhookSecret);
            Blob payloadBlob = Blob.valueOf(signedPayload);
            Blob hash = Crypto.generateMac(ALGORITHM, payloadBlob, secretBlob);
            String computedSignature = EncodingUtil.convertToHex(hash);
            
            return computedSignature.equals(expectedSignature);
            
        } catch (Exception e) {
            System.debug('Stripe signature verification error: ' + e.getMessage());
            return false;
        }
    }
    
    private Map<String, String> parseStripeSignature(String signature) {
        Map<String, String> parts = new Map<String, String>();
        String[] elements = signature.split(',');
        
        for (String element : elements) {
            String[] keyValue = element.split('=');
            if (keyValue.size() == 2) {
                parts.put(keyValue[0], keyValue[1]);
            }
        }
        
        return parts;
    }
}