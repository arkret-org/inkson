export const PRINCIPAL_HTTP_CORE_BUNDLE =
  "ak.operation_bundle.station.http_core_current.v1";
export const PRINCIPAL_DESCRIBE_BUNDLE =
  "ak.operation_bundle.station.describe.v1";
export const DIRECTORY_PUBLIC_READ_BUNDLE =
  "ak.operation_bundle.directory_service.public_read.v1";
export const DIRECTORY_DESCRIBE_BUNDLE =
  "ak.operation_bundle.directory_service.describe.v1";

export function currentHttpDescribeCapabilities(operationBundleIds, baseUrl) {
  return {
    supported_operation_bundles: [...operationBundleIds],
    transport_bindings: [
      {
        kind: "http_json",
        base_url: baseUrl ?? "https://server.local/_arkret",
        extension_profile_required: null,
      },
    ],
  };
}
