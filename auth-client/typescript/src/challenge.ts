export function bearerChallenge(metadataUrl: string, error?: string, description?: string): string {
  const values = [`resource_metadata="${escapeValue(metadataUrl)}"`];
  if (error) values.push(`error="${escapeValue(error)}"`);
  if (description) values.push(`error_description="${escapeValue(description)}"`);
  return `Bearer ${values.join(", ")}`;
}

export function unauthorizedHeaders(metadataUrl: string): Record<string, string> {
  return { "WWW-Authenticate": bearerChallenge(metadataUrl) };
}

function escapeValue(value: string): string {
  return value.replace(/["\\]/g, "\\$&").replace(/[\r\n]/g, " ");
}
