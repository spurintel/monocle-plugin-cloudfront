/** Lambda@Edge origin-request event and generated-response shapes. */

export interface EdgeHeader {
	key?: string;
	value: string;
}

export type EdgeHeaders = Record<string, EdgeHeader[]>;

export interface EdgeRequest {
	method: string;
	uri: string;
	querystring: string;
	clientIp: string;
	headers: EdgeHeaders;
	body?: { data?: string; encoding?: string; inputTruncated?: boolean };
}

export interface CloudFrontOriginRequestEvent {
	Records: {
		cf: {
			config?: { distributionDomainName?: string; distributionId?: string };
			request: EdgeRequest;
		};
	}[];
}

export interface EdgeResponse {
	status: string;
	statusDescription?: string;
	headers?: EdgeHeaders;
	body?: string;
	bodyEncoding?: 'text' | 'base64';
}

export interface Kvs {
	get(key: string): Promise<string | null>;
	update(puts: { key: string; value: string }[], deletes?: string[]): Promise<void>;
}
