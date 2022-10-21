<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Traits\ApiResponser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    use ApiResponser;
    private string $tokenName =  "API Token";


    public function register(Request $request)
    {
        $validator = Validator::make($request->all(),[
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|min:6'
        ]);

        if($validator->fails()){
            return $this->error('Validation failed!', 401,  $validator->errors());
        }else{
            $attr = $request->all();
            $attr['password'] = bcrypt($attr['password']);
            $user = User::create($attr);
            $user->assignRole('guest');
            return $this->success( [
                'token' => $user->createToken($this->tokenName)->plainTextToken
            ],"Successfully Completed");
        }


    }

    public function login(Request $request)
    {
        $attr = $request->all();


        $validator = Validator::make($attr,[
            'email' => 'required|email',
            'password' => 'required'
        ]);

        if($validator->fails()){
            return $this->error('Validation failed!', 401,  $validator->errors());
        }

        $attr = $request->all();

        if (!Auth::attempt($attr)) {
            return $this->error('Wrong credentials', 401);
        }

        return $this->success([
            'token' => auth()->user()->createToken($this->tokenName)->plainTextToken
        ]);

    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return $this->success([
            'message' => 'Successfully unathorized!'
        ]);
    }
}
