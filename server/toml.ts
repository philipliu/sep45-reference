async function fetchToml(domain: string): Promise<string> {
  const tomlUrl = `${domain}/.well-known/stellar.toml`;
  const response = await fetch(tomlUrl);

  if (!response.ok) {
    throw new Error(`Failed to fetch TOML file from ${tomlUrl}`);
  }

  return response.text();
}

export async function fetchSigningKey(domain: string): Promise<string> {
  const toml = await fetchToml(domain);
  const signingKey = toml
    .split("\n")
    .find((line) => line.startsWith("SIGNING_KEY"))
    ?.split("=")[1]
    ?.trim()
    ?.replace(/"/g, "");

  if (!signingKey) {
    throw new Error("SIGNING_KEY not found in TOML file");
  }

  return signingKey;
}
