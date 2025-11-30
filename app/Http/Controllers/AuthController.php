<?php

namespace App\Http\Controllers;

use App\Helpers\ResponseApi;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use App\Models\User;

/**
 * Class AuthController
 * 
 * Controller xử lý các chức năng liên quan đến xác thực:
 * - Đăng nhập bằng username/email + password
 * - Đăng nhập bằng Google
 * - Đăng ký người dùng mới
 */
class AuthController extends Controller
{
    private $responseApi;

    /**
     * Constructor
     * Khởi tạo helper ResponseApi để chuẩn hóa response
     */
    public function __construct()
    {
        $this->responseApi = new ResponseApi();
    }

    /**
     * LOGIN
     * Xử lý đăng nhập với username/email + password
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        try {
            $param = $request->all();

            // Tìm user theo username hoặc email
            $user = $this->findUser($request->user_name);

            // Nếu user không tồn tại hoặc bị banned
            if (!$user || $user->status == User::STATUS_BANNED) {
                return $this->responseApi->BadRequest('User not found or banned');
            }

            // Kiểm tra mật khẩu
            if (!Hash::check($param['password'], $user->password)) {
                return $this->responseApi->BadRequest('Password is incorrect');
            }

            // Đăng nhập user vào hệ thống
            Auth::login($user);

            // Tạo token API cho user
            $success = $user->createToken($user->id);

            // Lưu token vào DB (có thể dùng để logout device)
            $user->update([
                'device_token' => $success->accessToken
            ]);

            // Thêm thông tin user vào response
            $success->user_info = $user;

            return $this->responseApi->success($success);
        } catch (\Exception $e) {
            Log::error('Login error: ' . $e->getMessage());
            return $this->responseApi->BadRequest($e->getMessage());
        }
    }

    /**
     * LOGIN WITH GOOGLE
     * Xử lý đăng nhập bằng access_token của Google
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function loginWithGoogle(Request $request)
    {
        try {
            $accessToken = $request->input('access_token');

            // Gọi Google API lấy thông tin user
            $response = Http::withHeaders([
                'Authorization' => "Bearer $accessToken",
            ])->get('https://www.googleapis.com/oauth2/v3/userinfo');

            if ($response->failed()) {
                return response()->json(['error' => 'Invalid token'], 401);
            }

            $googleUser = $response->json();

            // Kiểm tra user trong hệ thống
            $user = $this->findUser($googleUser['email'], $googleUser['given_name']);

            // Nếu chưa có user thì tạo mới
            if (!$user) {
                $user = User::create([
                    'name' => $googleUser['name'],
                    'email' => $googleUser['email'],
                    'avatar' => $googleUser['picture'],
                    'role' => User::ROLE_CLIENT,
                    'status' => User::ONLINE_STATUS,
                    'online_status' => User::ONLINE_STATUS
                ]);
            }

            // Đăng nhập vào hệ thống
            Auth::login($user);

            // Tạo token API
            $success = $user->createToken($user->id);

            // Lưu token vào DB
            $user->update([
                'token' => $success->accessToken
            ]);

            // Thêm thông tin user vào response
            $success->user_info = $user;

            return $this->responseApi->success($success);
        } catch (\Exception $e) {
            Log::error('LoginWithGoogle error: ' . $e->getMessage());
            return $this->responseApi->InternalServerError();
        }
    }

    /**
     * REGISTER
     * Tạo tài khoản mới
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        try {
            $param = $request->all();

            // Kiểm tra user đã tồn tại chưa
            $user = $this->findUser($param['email'], $param['user_name']);
            if ($user) {
                return $this->responseApi->BadRequest('User already exists');
            }

            // Tạo user mới
            $user = User::create([
                'user_name' => $param['user_name'],
                'full_name' => $param['full_name'],
                'email' => $param['email'],
                'password' => Hash::make($param['password']),
                'role' => User::ROLE_CLIENT,
                'status' => User::STATUS_ACTIVE,
            ]);

            return $this->responseApi->success();
        } catch (\Exception $e) {
            Log::error('Register error: ' . $e->getMessage());
            return $this->responseApi->BadRequest('Error creating user: ' . $e->getMessage());
        }
    }

    /**
     * FIND USER
     * Tìm user theo email hoặc username
     *
     * @param string $emailOrUsername Email hoặc username
     * @param string|null $username Tùy chọn username (ví dụ khi kiểm tra register)
     * @return User|null
     */
    private function findUser($emailOrUsername, $username = null)
    {
        try {
            // Nếu chỉ truyền 1 giá trị (login/email/username)
            if ($username === null) {
                return User::where('email', $emailOrUsername)
                    ->orWhere('user_name', $emailOrUsername)
                    ->first();
            }

            // Nếu truyền cả email và username (ví dụ kiểm tra tồn tại khi đăng ký)
            return User::where('email', $emailOrUsername)
                ->orWhere('user_name', $username)
                ->first();
        } catch (\Exception $e) {
            Log::error('FindUser error: ' . $e->getMessage());
            return null;
        }
    }
}
