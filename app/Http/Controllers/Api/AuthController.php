<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\LoginRequest;
use App\Models\User;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(LoginRequest $request)
    {
        $user = User::whereEmail($request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['response' => false, 'message' => 'The given data was invalid.'], Response::HTTP_BAD_REQUEST);
        }

        $authToken = $user->createToken('auth_token')->plainTextToken;

        return response()->json(['response' => true, 'access_token' => $authToken], Response::HTTP_CREATED);
    }
}
