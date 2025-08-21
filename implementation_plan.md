# Implementation Plan

## Overview
Fix the `401 Unauthorized: invalid token` error in the Raycast extension when calling authenticator-specific endpoints by aligning the API client implementation with the official Ente CLI and web implementations.

The issue is not with token decryption or encoding (which is working correctly), but with missing headers, context, and validation differences between regular API endpoints and authenticator-specific endpoints. The extension successfully receives an email notification upon login (indicating successful authentication), but fails when accessing `/authenticator/key` and related endpoints.

## Types
Update API client interface to include additional authentication context and headers.

**Enhanced API Client Interface:**
```typescript
interface ApiClientConfig {
  token?: string;
  clientPackage: string;
  userId?: number;
  accountKey?: string;
}

interface AuthenticationContext {
  userId: number;
  accountKey: string;
  userAgent: string;
}
```

**Request Headers Interface:**
```typescript
interface AuthenticatedHeaders {
  'Content-Type': string;
  'X-Auth-Token': string;
  'X-Client-Package': string;
  'User-Agent'?: string;
  'X-Request-Id'?: string;
}
```

## Files
Modify existing API client and authentication flow to match official implementation patterns.

**Modified Files:**
- `ente-auth/src/services/api.ts` - Update API client with proper headers and context handling
- `ente-auth/src/services/authenticator.ts` - Add enhanced debugging and proper authentication context
- `ente-auth/src/login.tsx` - Store additional authentication context from login response
- `ente-auth/src/types.ts` - Add authentication context types
- `ente-auth/src/services/storage.ts` - Store and retrieve authentication context

**New Files:**
- None required - modifications to existing files only

## Functions
Add proper authentication context handling and debugging capabilities.

**Modified Functions:**

`api.ts`:
- `constructor()` - Accept and use client package configuration
- `setToken()` - Include authentication context when setting token
- `setAuthenticationContext()` - NEW: Set user ID and account key for authenticator operations
- `getAuthenticatedHeaders()` - NEW: Generate headers matching CLI implementation
- `testTokenValidity()` - Enhanced debugging with request/response logging

`authenticator.ts`:
- `init()` - Store and use authentication context from login
- `getDecryptionKey()` - Add context-aware API calls
- `syncAuthenticator()` - Use proper authentication context

`login.tsx`:
- `handleSubmit()` - Store authentication context (userId, account key) after successful login

`storage.ts`:
- `storeAuthenticationContext()` - NEW: Store auth context securely
- `getAuthenticationContext()` - NEW: Retrieve stored auth context

## Classes
Enhance existing EnteApiClient class with authentication context management.

**Modified Classes:**

`EnteApiClient`:
- Add `authContext` property for storing user authentication context
- Add `clientPackage` configuration for proper client identification
- Modify header generation to match CLI implementation
- Add request/response debugging capabilities
- Implement proper token validation with context

`AuthenticatorService`:
- Add authentication context awareness
- Enhance debugging for API operations
- Implement proper error handling for authentication failures

## Dependencies
No new dependencies required - using existing libraries.

All existing dependencies remain the same:
- `axios` for HTTP requests
- `@raycast/api` for local storage and UI
- `sodium-javascript` for cryptographic operations
- `argon2-wasm` for key derivation

## Testing
Comprehensive debugging and validation approach.

**Enhanced Debugging Strategy:**
1. Add request/response logging that matches CLI debug output format
2. Compare API calls side-by-side with working CLI implementation
3. Add token validation tests for different endpoint types
4. Implement step-by-step authentication flow validation
5. Add proper error handling with detailed error messages

**Test Cases:**
- Verify token works for regular endpoints (like user profile)
- Verify token works for authenticator endpoints (like `/authenticator/key`)
- Compare request headers between CLI and Raycast implementations
- Test authentication context persistence across app restarts

## Implementation Order
Sequential implementation to minimize conflicts and ensure proper integration.

1. **Update API Client Headers and Context** - Modify `api.ts` to include proper headers and authentication context management that matches CLI implementation

2. **Enhance Authentication Context Storage** - Update `storage.ts` and `types.ts` to store and retrieve authentication context (userId, accountKey) securely

3. **Update Login Flow** - Modify `login.tsx` to capture and store authentication context during successful login

4. **Enhance Authenticator Service** - Update `authenticator.ts` to use authentication context for API calls and add enhanced debugging

5. **Add Comprehensive Debugging** - Implement detailed logging throughout the authentication and API call chain to compare with CLI behavior

6. **Test and Validate** - Run the extension and compare debug output with CLI implementation to ensure alignment

7. **Final Integration Testing** - Verify that all authenticator operations work correctly with the updated authentication context
