// k6_script.js
import grpc from 'k6/net/grpc';
import { check, sleep, group } from 'k6';
import { SharedArray } from 'k6/data';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js'; // For generating unique IDs

// --- Configuration ---
const SERVER_ADDRESS = '[::1]:50051'; // 👈 UPDATE THIS to your gRPC server address
const PROTO_FILE = '../proto/identity_service.proto'; // Path to your .proto file

// It's good practice to load common Google protobufs if your main proto imports them explicitly
// and they aren't automatically found by k6.
// Often, k6 bundles these, but for clarity or if issues arise:
// const GOOGLE_PROTO_FILES_ROOT = './path/to/google/protos/'; // 👈 UPDATE if needed

const client = new grpc.Client();

// Load the protobuf definition.
// Ensure 'google/protobuf/timestamp.proto' and 'google/protobuf/empty.proto'
// are accessible if not bundled. k6 usually handles common Google protos.
// If you have them locally, you might need to specify include paths in client.load, e.g.,
// client.load(['.', GOOGLE_PROTO_FILES_ROOT], PROTO_FILE);
client.load(['.'], PROTO_FILE);

// --- Test Data (Optional but Recommended for more realistic tests) ---
// Example for pre-defined users for authentication tests or other scenarios
// const users = new SharedArray('users', function () {
//   // Load data from a JSON file
//   return JSON.parse(open('./users.json')); // expects a users.json file
// });

// --- Test Options ---
export const options = {
    thresholds: {
        'grpc_req_duration': ['p(95)<500'], // 95% of requests should be below 500ms
        'checks': ['rate>0.99'],            // Over 99% of checks should pass
    },
    // Example of stages for a more complex scenario (e.g., ramp-up, hold, ramp-down)
    // stages: [
    //   { duration: '10s', target: 5 },  // Ramp-up to 5 VUs over 10s
    //   { duration: '20s', target: 5 },  // Stay at 5 VUs for 20s
    //   { duration: '5s', target: 0 },   // Ramp-down to 0 VUs over 5s
    // ],
    // Example Stress Test Stages in options
    stages: [
        //{ duration: '30s', target: 50 }, // Ramp up to 10 VUs
        //{ duration: '1m', target: 40 },
        //{ duration: '1m', target: 80 }, // Ramp up to 50 VUs
        //{ duration: '1m', target: 100 },
        //{ duration: '1m', target: 300 },// Ramp up to 100 VUs
        //{ duration: '1m', target: 200 },
        //{ duration: '1m', target: 0 },   // Ramp down
        { duration: '1m', target: 1000 },   // Ramp down
    ],
};

// --- Setup function (runs once before the test) ---
export function setup() {
    // Connect to the gRPC server once for all VUs if using setup/teardown for global resources
    // client.connect(SERVER_ADDRESS, {
    //   plaintext: true, // Set to false if using TLS
    //   // reflect: true, // Enable if your server supports gRPC server reflection (alternative to loading proto)
    // });

    // You could pre-create some common test data here if needed
    // console.log('Setup complete. Starting test...');
    return { someData: 'Setup data can be passed to VUs' };
}

// --- Main VU function (runs in a loop for each VU) ---
export default function (dataFromSetup) {
    // Connect to the gRPC server for each VU.
    // This is often simpler if VUs don't need to share a single connection object.
    // If plaintext is false, you might need to configure TLS options.
    client.connect(SERVER_ADDRESS, {
        plaintext: true, // Set to false if using TLS
        // timeout: '5s' // Optional: specify connection timeout
    });

    let createdIdentityId = null;
    let createdUsername = `testuser_${uuidv4()}`;
    let createdEmail = `${createdUsername}@example.com`;
    let password = "securePassword123";

    group('IdentityService Operations', () => {
        // --- 1. CreateIdentity ---
        group('CreateIdentity', () => {
            const createPayload = {
                payload: {
                    first_name: 'Test',
                    last_name: 'User',
                    username: createdUsername,
                    email_address: createdEmail,
                    password_attempts: 0,
                    password: password, // Optional field
                    is_active: true,
                    is_verified: false,
                    is_enabled: true,
                },
            };
            const createResponse = client.invoke('identity.IdentityService/CreateIdentity', createPayload);

            check(createResponse, {
                'CreateIdentity: status is OK': (r) => r && r.status === grpc.StatusOK,
                'CreateIdentity: response has identity': (r) => r && r.message && r.message.identity && r.message.identity.id,
                'CreateIdentity: username matches': (r) => r && r.message && r.message.identity && r.message.identity.username === createdUsername,
            });

            if (createResponse && createResponse.message && createResponse.message.identity) {
                createdIdentityId = createResponse.message.identity.id;
                console.log(`VU ${__VU} ITER ${__ITER}: Created Identity ID: ${createdIdentityId}`);
            }
        });

        sleep(1); // Think time between operations

        // --- 2. GetIdentityById (only if creation was successful) ---
        if (createdIdentityId) {
            group('GetIdentityById', () => {
                const getByIdPayload = { id: createdIdentityId };
                const getByIdResponse = client.invoke('identity.IdentityService/GetIdentityById', getByIdPayload);

                check(getByIdResponse, {
                    'GetIdentityById: status is OK': (r) => r && r.status === grpc.StatusOK,
                    'GetIdentityById: response has identity': (r) => r && r.message && r.message.identity,
                    'GetIdentityById: ID matches': (r) => r && r.message && r.message.identity && r.message.identity.id === createdIdentityId,
                });
            });
            sleep(1);

            // --- 3. Authenticate (only if creation was successful) ---
            group('Authenticate', () => {
                const authPayload = {
                    id: createdIdentityId,
                    password: password,
                };
                const authResponse = client.invoke('identity.IdentityService/Authenticate', authPayload);
                check(authResponse, {
                    'Authenticate: status is OK': (r) => r && r.status === grpc.StatusOK,
                    'Authenticate: response has identity': (r) => r && r.message && r.message.identity && r.message.identity.id === createdIdentityId,
                    'Authenticate: identity is active': (r) => {
                        return r && r.message && r.message.identity && r.message.identity.isActive === true
                    },
                });
            });
            sleep(1);


            // --- 4. UpdateIdentity (Example - you can add more complex updates) ---
            group('UpdateIdentity', () => {
                const updatePayload = {
                    id: createdIdentityId,
                    updates: {
                        first_name: "UpdatedFirstName",
                        is_active: false, // Example update
                        // email_address: `updated_${createdEmail}` // Can also update other fields
                    }
                };
                const updateResponse = client.invoke('identity.IdentityService/UpdateIdentity', updatePayload);
                check(updateResponse, {
                    'UpdateIdentity: status is OK': (r) => r && r.status === grpc.StatusOK,
                    'UpdateIdentity: first name updated': (r) => r && r.message && r.message.identity && r.message.identity.firstName === "UpdatedFirstName",
                    'UpdateIdentity: is_active updated': (r) => r && r.message && r.message.identity && r.message.identity.isActive === false,
                });
            });
            sleep(1);

            // --- 5. DeleteIdentity (only if creation was successful) ---
            group('DeleteIdentity', () => {
                const deletePayload = { id: createdIdentityId };
                const deleteResponse = client.invoke('identity.IdentityService/DeleteIdentity', deletePayload);

                check(deleteResponse, {
                    'DeleteIdentity: status is OK': (r) => r && r.status === grpc.StatusOK,
                    'DeleteIdentity: response message is empty or as expected': (r) => r && r.message // For google.protobuf.Empty, message is often just {} or null
                });
            });
        } else {
            console.log(`VU ${__VU} ITER ${__ITER}: Skipping Get/Auth/Delete as CreateIdentity failed or didn't return an ID.`);
        }
    });

    // Close the connection at the end of the VU iteration.
    // Depending on your test and server, you might open/close per iteration or per VU (in setup/teardown).
    client.close();
    sleep(1); // Cooldown period at the end of an iteration
}

// --- Teardown function (runs once after the test) ---
export function teardown(data) {
    // client.close(); // Close the global client if it was opened in setup()
    console.log('Test finished. Teardown complete.');
    // You could perform global cleanup here, e.g., deleting all test entities created if IDs were collected.
}