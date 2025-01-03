/*
 * (C) 2020 Agilysys NV, LLC.  All Rights Reserved.  Confidential Information of Agilysys NV, LLC.
 */
package com.agilysys.pms.intproxy.handler;

import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

import javax.annotation.PostConstruct;
import javax.net.ssl.SSLContext;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import com.agilysys.pms.common.util.ExceptionUtils;
import com.agilysys.pms.intproxy.data.ApiLogRepository;
import com.agilysys.pms.intproxy.data.domain.ApiLogDomain;
import com.agilysys.pms.intproxy.data.domain.Status;
import com.agilysys.pms.relay.model.IntegrationRequestData;
import com.agilysys.pms.relay.model.IntegrationResponseData;

@Component
public class ProxyRequestHandler {
    private final Logger log = LoggerFactory.getLogger(ProxyRequestHandler.class);

    @Value("${AgilysysTrustStore.trustStorePassword:}")
    private String trustStorePassword;

    @Value("${AgilysysTrustStore.trustStoreLocation:}")
    private String trustStoreLocation;

    @Value("${intProxy.timeout:20000}")
    private int defaultRequestTimeoutMs;

    @Autowired
    private RequestValidator requestValidator;

    @Autowired
    private ApiLogRepository apiLogRepository;

    private SSLConnectionSocketFactory validatingSslSocketFactory;

    private SSLConnectionSocketFactory trustingSslSocketFactory;

    @PostConstruct
    public void init() throws Exception {
        if (StringUtils.isNoneBlank(trustStoreLocation, trustStorePassword)) {
            SSLContext sslContext = new SSLContextBuilder().setProtocol("TLSv1.2")
                  .loadTrustMaterial(new File(trustStoreLocation), trustStorePassword.toCharArray()).build();
            validatingSslSocketFactory = new SSLConnectionSocketFactory(sslContext);
        } else {
            log.warn("no trust store location or password defined");
        }

        TrustStrategy naiveTrustStrategy = (X509Certificate[] x, String y) -> true;
        SSLContext sslContext = new SSLContextBuilder().setProtocol("TLSv1.2")
              .loadTrustMaterial(null, naiveTrustStrategy).build();
        trustingSslSocketFactory = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());
    }

    public IntegrationResponseData process(IntegrationRequestData requestData) {
        requestValidator.validate(requestData);
        ApiLogDomain apiLog = createApiLog(requestData);

        IntegrationResponseData responseData = new IntegrationResponseData();
        try {
            log.debug("Processing request: {}", requestData.getUrl());
            RestTemplate rt = getRestTemplate(requestData);
            HttpEntity<byte[]> requestEntity = new HttpEntity<>(requestData.getBody(), requestData.getHeaders());

            ResponseEntity<byte[]> re =
                  rt.exchange(requestData.getUrl(), requestData.getMethodType(), requestEntity, byte[].class);
            loadResponse(responseData, re.getStatusCode(), re.getHeaders(), re.getBody(), true);
            apiLog.setStatus(Status.COMPLETED_SUCCESS);
            apiLog.setResponseCode(re.getStatusCode().value());
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("Error from the server", e);
            loadResponse(responseData, e.getStatusCode(), e.getResponseHeaders(), e.getResponseBodyAsByteArray(),
                  false);
            apiLog.setResponseCode(e.getStatusCode().value());
        } catch (Exception e) {
            log.error("Error while processing the request", e);
            loadResponse(responseData, HttpStatus.INTERNAL_SERVER_ERROR, null,
                  ExceptionUtils.rootCauseStackTrace(e).getBytes(), false);
            apiLog.setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
        } finally {
            log.debug("Request {} is completed: {}", requestData.getUrl(), responseData.getStatus());
            if (apiLog.getStatus() != Status.COMPLETED_SUCCESS) {
                apiLog.setStatus(Status.COMPLETED_FAILED);
            }
            updateApiLog(responseData, apiLog);
        }

        return responseData;
    }

    private ApiLogDomain createApiLog(IntegrationRequestData requestData) {
        String requestBody = requestData.getBody() != null ? convertToString(requestData.getBody()) : null;
        ApiLogDomain apiLog =
              new ApiLogDomain(requestData.getOtaTransactionId(), Status.IN_PROGRESS, requestData.getUrl(), requestBody,
                    DateTime.now());
        apiLogRepository.insert(apiLog);

        return apiLog;
    }

    private void updateApiLog(IntegrationResponseData responseData, ApiLogDomain apiLogDomain) {
        if (responseData.getBody() != null) {
            apiLogDomain.setResponseBody(convertToString(responseData.getBody()));
        }

        apiLogDomain.setFinished(DateTime.now());
        apiLogRepository.updateApiLog(apiLogDomain);
    }

    private RestTemplate getRestTemplate(IntegrationRequestData request) throws Exception {
        HttpClientBuilder httpClientBuilder = HttpClients.custom();

        if ("https".equals(new URI(request.getUrl()).getScheme())) {
            if (request.isInsecureSsl() != null && request.isInsecureSsl()) {
                httpClientBuilder.setSSLSocketFactory(trustingSslSocketFactory);
                log.warn("Insecure SSL forced in - url: {} otaId: {}", request.getUrl(), request.getOtaTransactionId());
            } else if (validatingSslSocketFactory != null) {
                httpClientBuilder.setSSLSocketFactory(validatingSslSocketFactory);
            } else {
                log.warn("No valid SSL settings found");
            }
        }

        int timeout = defaultRequestTimeoutMs;
        if (request.getTimeout() != null && request.getTimeout() > 0) {
            timeout = request.getTimeout();
        }
        HttpComponentsClientHttpRequestFactory factory =
              new HttpComponentsClientHttpRequestFactory(httpClientBuilder.build());
        factory.setConnectTimeout(timeout);
        factory.setConnectionRequestTimeout(timeout);
        factory.setReadTimeout(timeout);

        return new RestTemplate(factory);
    }

    private static String convertToString(byte[] body) {
        return new String(body, StandardCharsets.UTF_8);
    }

    private static void loadResponse(IntegrationResponseData responseData, HttpStatus status, HttpHeaders httpHeaders,
          byte[] body, boolean success) {
        responseData.setStatus(status);
        responseData.setHeaders(httpHeaders);
        responseData.setBody(body);
        responseData.setTransactionSuccess(success);
    }
}

class Bad {
    public void bad_disable_old_tls1() {
        //ruleid: disallow-old-tls-versions1
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }

    public void bad_disable_old_tls2() {
        //ruleid: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }

    public void bad_disable_old_tls2() {
        //ruleid: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1", "TLSv1.1", "SSLv3"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }
}

class Ok {
    public void ok_disable_old_tls1() {
        //ok: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1.2"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }

    public void ok_disable_old_tls2() {
        //ok: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1.2", "TLSv1.3"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }

    public void ok_disable_old_tls3() {
        //ok: disallow-old-tls-versions1
        SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(
                sslContext,
                new String[] {"TLSv1.3"},
                null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
    }

    public void ok_disable_old_tls4() {
            TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
			SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
            //ok: disallow-old-tls-versions1
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);
			TlsConfig tlsConfig = TlsConfig.custom().setHandshakeTimeout(Timeout.ofSeconds(30)).setSupportedProtocols(TLS.V_1_3).build();
			HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create().setSSLSocketFactory(csf).setDefaultTlsConfig(tlsConfig).build();
			CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(cm).build();
			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
			requestFactory.setHttpClient(httpClient);
			restTemplate = new RestTemplate(requestFactory);
    }
}
